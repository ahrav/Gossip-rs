//! Git persistence adapters and repo-frontier durability helpers.
//!
//! # Purpose
//!
//! `scanner-git` splits Git durability across several trait seams:
//! [`SeenBlobStore`] for duplicate-OID queries, [`RefWatermarkStore`] for
//! incremental-scan bookmarks, [`SeenBitmapPersister`] for spill-stage
//! staging writes, and [`PersistenceStore`] for atomic finalize commits.
//! This module unifies all four behind a single runtime-owned
//! [`GitPersistenceBackend`] so a repo-frontier worker can:
//!
//! - load ref watermarks from durable state,
//! - answer seen-blob queries from the committed seen-bitmap scope,
//! - stage incremental seen deltas between finalize calls, and
//! - convert a durably committed complete finalize into the shared
//!   repo-frontier receipt/checkpoint path consumed by the runtime.
//!
//! # Seen-bitmap staging protocol
//!
//! Between finalize calls the scan pipeline spills processed OIDs through
//! [`SeenBitmapPersister::persist_seen_delta`]. These land in a **staging
//! key** that is invisible to [`SeenBlobStore::batch_check_seen`] — the
//! query path reads only from the committed **scope key**. On a complete
//! finalize, staging OIDs are merged into the scope key atomically (or in
//! a crash-safe multi-phase write on non-atomic backends). On a partial
//! finalize, staging OIDs are discarded because they may include blobs
//! from skipped candidates.
//!
//! # Complete vs. partial finalizes
//!
//! Complete finalizes yield repo-frontier progress (a [`UnitCommitReceipt`]
//! and [`CheckpointAggregatorInput`]). Partial finalizes commit data-ops
//! seen deltas (genuinely scanned blobs) but suppress watermark advancement
//! and outer checkpoint progress because their watermark state is
//! intentionally non-authoritative.

use std::cell::{Cell, RefCell};
use std::io;
use std::num::NonZeroU64;

#[cfg(test)]
use gossip_contracts::persistence::derive_ovid_hash;
use gossip_contracts::{
    connector::Cursor,
    connector::VersionId,
    connector::git::RepoKey,
    identity::{ObjectVersionId, StableItemId},
    persistence::{
        CommitScope, DoneLedgerCommitReceipt, FindingsCommitReceipt, OvidHashInputs, PageCommit,
        PageCommitValidationError, PersistenceInputError, WriteContext,
    },
};
use scanner_git::{
    FinalizeOutcome, FinalizeOutput, NS_SEEN_BLOB, OidBytes, PersistError, PersistenceStore,
    RefWatermark, RefWatermarkStore, RepoOpenError, SeenBitmapDelta, SeenBitmapPersister,
    SeenBlobStore, SpillError, StartSetId, WriteOp, decode_ref_watermark_value,
    finalize::{build_ref_wm_key, build_seen_scope_key, build_seen_staging_key},
    roaring_seen::{RoaringSeenBitmap, RoaringSeenStore},
};

use crate::commit_model::{
    BoundaryMismatchError, CheckpointAggregatorInput, CompletedUnit, KindMismatchError,
    UnitCommitReceipt,
};

/// One backend operation applied by [`GitPersistenceBackend::apply_batch`].
///
/// Keys and values are opaque byte slices built by `scanner-git`'s
/// finalize layer. Deterministic keys make `Put` and `Delete` idempotent,
/// so replaying a batch after a crash is safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitPersistenceOp {
    /// Store or overwrite the given value at `key`.
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Remove the given `key` from durable state.
    Delete { key: Vec<u8> },
}

impl GitPersistenceOp {
    /// Convert a `scanner-git` [`WriteOp`] into a `Put` operation by cloning
    /// the key and value. Used during finalize to translate scanner output
    /// into backend-level operations.
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
    ///
    /// The default implementation calls [`get`](Self::get) in a loop and
    /// short-circuits on the first error (the iterator collects into
    /// `Result<Vec<_>, _>`). Override this if your backend supports a
    /// native multi-get that can return partial results or better error
    /// granularity.
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
    /// The done-ledger record failed construction or validation.
    #[error("git repo done-ledger record invalid: {0}")]
    InvalidDoneLedgerRecord(#[source] PersistenceInputError),
}

/// Runtime adapter that satisfies all four `scanner-git` persistence traits
/// ([`SeenBlobStore`], [`RefWatermarkStore`], [`SeenBitmapPersister`], and
/// [`PersistenceStore`]) by delegating to one [`GitPersistenceBackend`].
///
/// # Caching strategy
///
/// The adapter lazily loads the committed seen-bitmap from the backend on
/// first `batch_check_seen` call and caches it for subsequent queries.
/// Spill-stage `persist_seen_delta` writes target a separate staging key
/// and accumulate in `staging_seen`; they remain invisible to
/// `batch_check_seen` until a complete finalize merges them into the
/// committed scope key.
///
/// # Single-writer constraint
///
/// Access is single-threaded. `scanner-git` calls these methods on the scan
/// thread before or after pack workers run, never concurrently. At most one
/// adapter instance may operate on a given `(repo_id, policy_hash)` scope
/// because the staging bitmap read-modify-write in `persist_seen_delta` is
/// not atomic across instances.
///
/// # Fields
///
/// - `seen_store`: cached committed scope bitmap (lazy-loaded from backend).
/// - `staging_seen`: in-memory accumulator for spill-stage OIDs (written
///   through to backend on each `persist_seen_delta`, merged into scope on
///   complete finalize).
/// - `finalizing`: re-entrancy guard for `commit_finalize`.
#[derive(Debug)]
pub struct GitPersistenceAdapter<B> {
    backend: B,
    repo_id: u64,
    policy_hash: [u8; 32],
    seen_store: RefCell<Option<RoaringSeenStore>>,
    staging_seen: RefCell<Option<RoaringSeenBitmap>>,
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
            staging_seen: RefCell::new(None),
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
    /// Synthesizes the `CompletedUnit`, `CommitScope`, and `PageCommit`
    /// chain that the runtime checkpoint path expects. The caller provides
    /// the actual `FindingsCommitReceipt` and `DoneLedgerCommitReceipt`
    /// from the persistence layer so the receipt accurately reflects
    /// durable findings and done-ledger state.
    ///
    /// Complete finalizes yield a receipt. Partial finalizes return `None`
    /// because their watermark state is intentionally non-authoritative.
    pub fn repo_frontier_receipt(
        &self,
        write_context: WriteContext,
        sequence_no: u64,
        repo_key: &RepoKey,
        outcome: FinalizeOutcome,
        findings_receipt: FindingsCommitReceipt,
        done_ledger_receipt: DoneLedgerCommitReceipt,
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
            .record_findings(findings_receipt)
            .record_done_ledger(done_ledger_receipt)
            .map_err(GitRepoDurabilityError::InvalidItemReceipt)?
            .into_item_commit_receipt();

        UnitCommitReceipt::new(completed_unit, durable)
            .map(Some)
            .map_err(GitRepoDurabilityError::BoundaryMismatch)
    }

    /// Build the outer repo-frontier checkpoint input for one already-committed finalize.
    ///
    /// Wraps [`repo_frontier_receipt`](Self::repo_frontier_receipt) with a
    /// [`CheckpointAggregatorInput`] that validates boundary-kind consistency.
    ///
    /// Complete finalizes yield checkpoint input. Partial finalizes return
    /// `None` so outer progress remains unchanged.
    pub fn repo_frontier_checkpoint_input(
        &self,
        write_context: WriteContext,
        sequence_no: u64,
        repo_key: &RepoKey,
        outcome: FinalizeOutcome,
        findings_receipt: FindingsCommitReceipt,
        done_ledger_receipt: DoneLedgerCommitReceipt,
    ) -> Result<Option<CheckpointAggregatorInput>, GitRepoDurabilityError> {
        let Some(receipt) = self.repo_frontier_receipt(
            write_context,
            sequence_no,
            repo_key,
            outcome,
            findings_receipt,
            done_ledger_receipt,
        )?
        else {
            return Ok(None);
        };

        CheckpointAggregatorInput::new(receipt.completed_unit().checkpoint_boundary_kind(), receipt)
            .map(Some)
            .map_err(GitRepoDurabilityError::KindMismatch)
    }

    /// Backend key for the committed seen-bitmap (authoritative scope).
    /// Queries in `batch_check_seen` read this key.
    fn seen_scope_key(&self) -> Vec<u8> {
        build_seen_scope_key(self.repo_id, &self.policy_hash)
    }

    /// Backend key for the staging seen-bitmap (spill accumulator).
    /// Written by `persist_seen_delta`, merged into the scope key on
    /// complete finalize, deleted on both complete and partial finalize.
    fn seen_staging_key(&self) -> Vec<u8> {
        build_seen_staging_key(self.repo_id, &self.policy_hash)
    }
}

/// Cloned adapters share the backend but start with empty seen-bitmap and
/// staging caches plus a fresh `finalizing` flag. This deliberate reset
/// enforces the single-writer invariant: each adapter instance independently
/// loads its cache from the backend, preventing stale cache propagation.
///
/// **Single-writer constraint**: at most one adapter instance may operate on
/// a given `(repo_id, policy_hash)` scope at any time. The staging bitmap
/// read-modify-write in `persist_seen_delta` is not atomic across instances.
/// The scan lifecycle enforces this — one scan thread per repository — so
/// callers do not need additional synchronization.
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
    /// Ensure the cached seen-store is populated and has the correct OID length.
    ///
    /// Reloads from the backend when the cache is empty or when the cached
    /// bitmap's OID length does not match `oid_len` (which would indicate a
    /// schema change between scan runs).
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

    /// Cold-path: read and deserialize the committed scope bitmap from the
    /// backend. Returns an empty bitmap when no scope key exists yet (first
    /// scan of this repo/policy pair).
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

/// Spill-stage persistence: accumulates processed OIDs in the staging bitmap.
///
/// Each call merges the supplied OIDs into a cached staging bitmap, then
/// writes the merged result to the staging key. The staging bitmap is
/// invisible to `batch_check_seen` and only folded into the committed scope
/// on a complete finalize.
///
/// # Take-mutate-restore caching
///
/// The bitmap is moved out of the cache (`Option::take`), merged in place,
/// serialized, and restored only after the backend write succeeds. A failed
/// `apply_batch` leaves the cache empty; the next call reloads from the
/// backend, which always holds the last successfully written state. This
/// avoids cloning the full bitmap on every batch (O(total) per call)
/// while preserving the invariant that `commit_finalize` never folds
/// phantom OIDs into the committed scope.
///
/// # Amortized cost
///
/// The staging bitmap is loaded from the backend on the first spill call,
/// then cached for subsequent batches. This reduces aggregate I/O from
/// O(N^2/B) (re-reading the growing bitmap per batch) to O(N) where N is
/// total staged OIDs.
impl<B> SeenBitmapPersister for GitPersistenceAdapter<B>
where
    B: GitPersistenceBackend,
{
    fn persist_seen_delta(&self, oids: &[OidBytes]) -> Result<(), SpillError> {
        if oids.is_empty() {
            return Ok(());
        }

        debug_assert!(
            oids.windows(2).all(|w| w[0] < w[1]),
            "persist_seen_delta requires sorted unique OIDs"
        );
        let delta = SeenBitmapDelta::from_canonical_oids(oids.to_vec())?;
        let staging_key = self.seen_staging_key();

        // Take ownership of the cached staging bitmap instead of cloning.
        // This turns the per-batch cost from O(total_bitmap) (clone) to
        // O(delta) (in-place merge). On backend write failure the cache
        // is empty; the next call reloads from the backend via the
        // `None` branch, which always holds the last successfully
        // written state.
        let mut guard = self.staging_seen.borrow_mut();
        let mut merged = match guard.take() {
            Some(bitmap) => bitmap,
            None => match self.backend.get(&staging_key) {
                Ok(Some(existing)) => RoaringSeenBitmap::deserialize(&existing).map_err(|err| {
                    SpillError::Io(io::Error::other(format!("corrupt staging bitmap: {err}")))
                })?,
                Ok(None) => RoaringSeenBitmap::new(delta.oid_len()),
                Err(err) => {
                    return Err(SpillError::Io(io::Error::other(format!(
                        "staging bitmap read failed: {err}"
                    ))));
                }
            },
        };
        merged.merge_delta(&delta)?;
        let bytes = merged.serialize()?;

        self.backend
            .apply_batch(&[GitPersistenceOp::Put {
                key: staging_key,
                value: bytes,
            }])
            .map_err(|err| {
                SpillError::Io(io::Error::other(format!(
                    "staging seen-bitmap write failed: {err}"
                )))
            })?;

        // Install the merged bitmap into the cache only after the
        // backend write succeeds.
        *guard = Some(merged);
        Ok(())
    }
}

/// Committed-scope queries: checks OIDs against the durable seen-bitmap only.
///
/// Staging OIDs are intentionally invisible here. The scan pipeline relies
/// on this separation to avoid false positives from OIDs that may belong to
/// skipped candidates (which would be discarded on partial finalize).
///
/// # Preconditions (debug-asserted)
///
/// - Must not be called during `commit_finalize` (the `finalizing` flag
///   guards against this).
/// - All OIDs must have the same byte length.
/// - OIDs must be sorted in ascending order with no duplicates.
impl<B> SeenBlobStore for GitPersistenceAdapter<B>
where
    B: GitPersistenceBackend,
{
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        debug_assert!(
            !self.finalizing.get(),
            "batch_check_seen called during commit_finalize"
        );
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        debug_assert!(
            oids.iter().all(|o| o.len() == oids[0].len()),
            "mixed OID lengths in batch_check_seen"
        );
        debug_assert!(
            oids.windows(2).all(|w| w[0] < w[1]),
            "batch_check_seen requires sorted unique OIDs"
        );

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

/// Incremental-scan bookmark loading from the backend.
///
/// Watermark keys are scoped to `(repo_id, policy_hash, start_set_id, ref_name)`.
/// The adapter validates that the caller's `repo_id` and `policy_hash` match
/// the adapter's identity before issuing backend reads, because a mismatch
/// would silently cross-pollinate watermarks between different scan scopes.
///
/// Returns one `Option<RefWatermark>` per input ref name, preserving input order.
/// `None` means no watermark exists for that ref (first scan or ref was pruned).
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
    ) -> Result<Vec<Option<RefWatermark>>, RepoOpenError> {
        // Watermark keys and seen-bitmap keys must be scoped to the same
        // (repo_id, policy_hash) identity. A mismatch would silently return
        // watermarks for a different scope than the seen-bitmap uses.
        if repo_id != self.repo_id || policy_hash != self.policy_hash {
            return Err(RepoOpenError::io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "load_watermarks identity mismatch: caller ({repo_id}, {:x?}) \
                     vs adapter ({}, {:x?})",
                    &policy_hash[..4],
                    self.repo_id,
                    &self.policy_hash[..4]
                ),
            )));
        }

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
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Some(value) => {
                    let decoded = decode_ref_watermark_value(&value).ok_or_else(|| {
                        RepoOpenError::io(io::Error::other(format!(
                            "invalid watermark value encoding for ref {i} ({} bytes)",
                            value.len()
                        )))
                    })?;
                    out.push(Some(decoded));
                }
                None => out.push(None),
            }
        }
        Ok(out)
    }
}

/// Atomic finalize commit: merges data ops, seen deltas, staging, and
/// watermarks into durable state.
///
/// # Algorithm (high level)
///
/// 1. **Re-entrancy guard**: rejects concurrent `commit_finalize` calls via
///    the `finalizing` flag (RAII-cleared on drop).
/// 2. **Classify data ops**: separates seen-bitmap deltas (namespace
///    `NS_SEEN_BLOB`) from non-seen data ops. Validates that any seen-bitmap
///    op matches this adapter's scope key.
/// 3. **Resolve staging**: takes the cached staging bitmap (populated by
///    `persist_seen_delta`), falling back to a backend read for crash
///    recovery when the cache is cold. On complete finalize, staging OIDs
///    are merged into the seen set; on partial finalize, they are discarded.
/// 4. **Merge seen bitmap**: loads the committed scope bitmap, merges all
///    collected OIDs (from data ops and staging), serializes, and adds a
///    `Put` for the scope key.
/// 5. **Write phases**: either a single atomic batch (when the backend
///    supports it) or a crash-safe multi-phase sequence:
///    - Phase 1: data ops + merged seen scope key
///    - Phase 2: delete staging key
///    - Phase 3: watermark ops (complete finalize only)
/// 6. **Cache update**: the seen-store cache is refreshed only after its
///    corresponding backend write succeeds.
///
/// # Crash safety on non-atomic backends
///
/// Data and seen-bitmap writes land before watermarks. If a crash occurs
/// between phases, the seen bitmap is already advanced but watermarks remain
/// at the old position. The next scan re-walks the same commit range but
/// skips already-seen blobs, producing no duplicate findings.
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

        if self.finalizing.replace(true) {
            return Err(PersistError::backend(
                "re-entrant commit_finalize calls violate the single-writer invariant",
            ));
        }
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
        if !matches!(output.outcome, FinalizeOutcome::Complete) && !output.watermark_ops.is_empty()
        {
            return Err(PersistError::backend(
                "watermark ops present for partial finalize outcome",
            ));
        }

        let seen_scope_key = self.seen_scope_key();
        let seen_staging_key = self.seen_staging_key();
        let seen_namespace = NS_SEEN_BLOB.as_slice();

        // Step 2: partition data ops into non-seen ops (forwarded as-is)
        // and seen-bitmap deltas (accumulated into `seen_oids` for merge).
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

        // Take the cached staging bitmap (populated by persist_seen_delta).
        // Fall back to a backend read for adapters that were constructed
        // after spill writes already landed (e.g., crash recovery).
        let staging_bitmap = self.staging_seen.borrow_mut().take();
        let staging_from_backend = if staging_bitmap.is_none() {
            match self.backend.get(&seen_staging_key) {
                Ok(Some(bytes)) => {
                    let bitmap = RoaringSeenBitmap::deserialize(&bytes).map_err(|err| {
                        PersistError::backend(format!("corrupt staging bitmap: {err}"))
                    })?;
                    Some(bitmap)
                }
                Ok(None) => None,
                Err(err) => {
                    return Err(PersistError::backend(format!(
                        "staging bitmap read failed: {err}"
                    )));
                }
            }
        } else {
            None
        };
        let resolved_staging = staging_bitmap.or(staging_from_backend);
        let has_staging = resolved_staging.is_some();
        if is_complete && let Some(staging) = &resolved_staging {
            // All OIDs in the staging bitmap must be marked seen. A mismatch
            // indicates a corrupt serialized payload (e.g., from a crash during
            // the non-atomic write path). Folding unseen OIDs into the live set
            // would permanently suppress future detection of those blobs.
            if staging.len() != staging.index_len() {
                return Err(PersistError::backend(
                    "staging bitmap contains unseen entries",
                ));
            }
            seen_oids.extend(staging.all_oids());
        }

        let mut staged_bitmap = None;
        if !seen_oids.is_empty() {
            // Both sources are already sorted; `from_oids` re-sorts as a
            // simplicity trade-off.
            let delta = SeenBitmapDelta::from_oids(&seen_oids)
                .map_err(|err| PersistError::backend(err.to_string()))?;
            let oid_len = delta.oid_len();

            self.load_seen_store(oid_len)
                .map_err(PersistError::backend)?;
            // Take ownership of the cached bitmap to avoid cloning. The
            // cache is repopulated with the merged result below.
            let merged = {
                let base = self.seen_store.borrow_mut().take().map_or_else(
                    || RoaringSeenBitmap::new(oid_len),
                    RoaringSeenStore::into_bitmap,
                );
                let mut staged = base;
                staged
                    .merge_delta(&delta)
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
            if has_staging {
                all_ops.push(GitPersistenceOp::Delete {
                    key: seen_staging_key,
                });
            }
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

        // Non-atomic path: write data+seen first, then advance watermarks.
        //
        // For complete finalize, the staging Delete is in a separate batch
        // AFTER the seen scope Put so a crash between batches cannot lose
        // staged OIDs (the scope key already contains them).
        //
        // For partial finalize, there is no seen scope Put — staging OIDs
        // are discarded. The staging Delete goes in first_phase_ops (same
        // batch as data ops) so a failed batch doesn't leave stale staging
        // for a later complete run to fold.
        //
        // Recovery posture: if the watermark write fails, the seen bitmap
        // is already durable and the in-memory cache reflects it. Callers
        // that retry with a fresh adapter will re-load the advanced seen
        // bitmap from the backend while watermarks remain at the old
        // position. The next scan re-walks the same commit range but skips
        // already-seen blobs, producing no duplicate findings.
        if has_staging && !is_complete {
            first_phase_ops.push(GitPersistenceOp::Delete {
                key: seen_staging_key.clone(),
            });
        }
        if !first_phase_ops.is_empty() {
            self.backend
                .apply_batch(&first_phase_ops)
                .map_err(|err| PersistError::backend(err.to_string()))?;
        }
        if let Some(bitmap) = staged_bitmap {
            *self.seen_store.borrow_mut() = Some(RoaringSeenStore::new(bitmap));
        }
        if has_staging && is_complete {
            self.backend
                .apply_batch(&[GitPersistenceOp::Delete {
                    key: seen_staging_key,
                }])
                .map_err(|err| PersistError::backend(err.to_string()))?;
        }
        if !watermark_ops.is_empty() {
            self.backend
                .apply_batch(&watermark_ops)
                .map_err(|err| PersistError::backend(err.to_string()))?;
        }
        Ok(())
    }
}

/// Identity inputs used when treating a Git repo as a persistence item.
///
/// Git repos have no object-version concept at the done-ledger level, so the
/// repo itself is the logical item and a fixed zero version keeps the
/// `(tenant, policy, repo_id)` mapping stable across scans.
pub(crate) fn git_repo_ovid_inputs(repo_id: u64) -> OvidHashInputs {
    let mut buf = [0u8; 32];
    buf[..8].copy_from_slice(&repo_id.to_le_bytes());
    OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(buf),
        version: VersionId::Strong(ObjectVersionId::from_bytes([0u8; 32])),
    }
}

/// In-memory [`GitPersistenceBackend`] for integration and unit tests.
///
/// Provides a `BTreeMap`-backed KV store with fault injection hooks
/// (positional batch faults, content-aware batch fault queues,
/// per-call get/multi_get fault queues), phase-annotated operation
/// logging, and batch recording.
/// Gated behind `cfg(test)` (unit tests in this crate) and the
/// `test-support` feature (integration tests in downstream crates).
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use scanner_git::{NS_BLOB_CTX, NS_FINDING, NS_REF_WATERMARK, NS_SEEN_STAGING};

    use super::{GitPersistenceBackend, GitPersistenceOp, NS_SEEN_BLOB};

    /// Error type returned by [`TestBackend`] when fault injection fires.
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    #[error("{message}")]
    pub struct TestBackendError {
        /// Static message describing the injected failure.
        pub message: &'static str,
    }

    /// Categorizes a backend key by the durable-state namespace encoded in
    /// its prefix (e.g., blob context, finding, watermark).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum KeyNamespace {
        BlobCtx,
        Finding,
        SeenScope,
        SeenStaging,
        Watermark,
    }

    impl KeyNamespace {
        /// Classifies a key by its namespace prefix.
        ///
        /// Panics on unrecognized prefixes so that new namespaces added in
        /// production code are immediately surfaced in test failures rather
        /// than silently falling through.
        pub fn from_key(key: &[u8]) -> Self {
            if key.starts_with(&NS_BLOB_CTX) {
                Self::BlobCtx
            } else if key.starts_with(&NS_FINDING) {
                Self::Finding
            } else if key.starts_with(&NS_SEEN_BLOB) {
                Self::SeenScope
            } else if key.starts_with(&NS_SEEN_STAGING) {
                Self::SeenStaging
            } else if key.starts_with(&NS_REF_WATERMARK) {
                Self::Watermark
            } else {
                panic!("unrecognized namespace prefix in key: {key:02x?}")
            }
        }
    }

    /// One logged backend operation annotated with the namespace of its key,
    /// enabling write-phase ordering and presence/absence verification.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SimBackendOp {
        ns: KeyNamespace,
        pub op: GitPersistenceOp,
    }

    impl SimBackendOp {
        /// Constructs a log entry, deriving the namespace from the op's key.
        pub fn new(op: GitPersistenceOp) -> Self {
            Self {
                ns: KeyNamespace::from_key(op_key(&op)),
                op,
            }
        }

        /// Returns the namespace this operation belongs to.
        pub fn ns(&self) -> KeyNamespace {
            self.ns
        }
    }

    /// Determines when a queued batch fault fires.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum BatchFaultTrigger {
        /// Fires on any `apply_batch` call regardless of key content.
        Any,
        /// Fires only when at least one op key starts with the given prefix.
        KeyPrefix(&'static [u8]),
    }

    impl BatchFaultTrigger {
        pub fn any() -> Self {
            Self::Any
        }

        pub fn key_prefix(prefix: &'static [u8]) -> Self {
            assert!(
                !prefix.is_empty(),
                "empty prefix matches every key; use BatchFaultTrigger::Any instead"
            );
            Self::KeyPrefix(prefix)
        }
    }

    /// Fault mode injected into `get` or `multi_get` calls.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum GetFault {
        /// Return an error.
        Fail,
        /// Truncate each returned value to at most `max_len` bytes.
        /// A present key with `max_len: 0` returns `Some(vec![])` (empty value),
        /// not `None` (absent key).
        Truncate { max_len: usize },
    }

    /// Extracts the key bytes from a persistence operation.
    fn op_key(op: &GitPersistenceOp) -> &[u8] {
        match op {
            GitPersistenceOp::Put { key, .. } | GitPersistenceOp::Delete { key } => key.as_slice(),
        }
    }

    /// Truncates an optional value to at most `max_len` bytes.
    fn truncate_value(value: Option<Vec<u8>>, max_len: usize) -> Option<Vec<u8>> {
        value.map(|mut bytes| {
            bytes.truncate(max_len);
            bytes
        })
    }

    /// Applies a single-value get fault: either returns an error or truncates.
    fn apply_get_fault_value(
        value: Option<Vec<u8>>,
        fault: GetFault,
    ) -> Result<Option<Vec<u8>>, TestBackendError> {
        match fault {
            GetFault::Fail => Err(TestBackendError {
                message: "injected get failure",
            }),
            GetFault::Truncate { max_len } => Ok(truncate_value(value, max_len)),
        }
    }

    /// Applies a batch get fault: either returns an error or truncates all values.
    fn apply_get_fault_values(
        values: Vec<Option<Vec<u8>>>,
        fault: GetFault,
    ) -> Result<Vec<Option<Vec<u8>>>, TestBackendError> {
        match fault {
            GetFault::Fail => Err(TestBackendError {
                message: "injected get failure",
            }),
            GetFault::Truncate { max_len } => Ok(values
                .into_iter()
                .map(|value| truncate_value(value, max_len))
                .collect()),
        }
    }

    /// Mutable interior state shared across clones of a [`TestBackend`].
    #[derive(Debug, Default)]
    pub struct TestBackendState {
        pub(super) kv: BTreeMap<Vec<u8>, Vec<u8>>,
        pub(super) batches: Vec<Vec<GitPersistenceOp>>,
        pub(super) batch_call_count: usize,
        pub(super) multi_get_truncate: bool,
        pub(super) op_log: Vec<SimBackendOp>,
        pub(super) batch_faults: Vec<BatchFaultTrigger>,
        pub(super) batch_fault_idx: usize,
        pub(super) get_faults: Vec<(usize, GetFault)>,
        pub(super) get_fault_count: usize,
        pub(super) multi_get_faults: Vec<(usize, GetFault)>,
        pub(super) multi_get_fault_count: usize,
        pub(super) phase_logging: bool,
    }

    /// In-memory backend with fault injection and batch recording.
    ///
    /// All clones share the same underlying state via `Rc<RefCell<_>>`.
    /// Not `Send` — intended for single-threaded test contexts only.
    #[derive(Debug, Clone, Default)]
    pub struct TestBackend {
        state: Rc<RefCell<TestBackendState>>,
        atomic: bool,
    }

    impl TestBackend {
        /// Creates a backend that reports atomic batch support.
        pub fn atomic() -> Self {
            Self {
                state: Rc::new(RefCell::new(TestBackendState::default())),
                atomic: true,
            }
        }

        /// Creates a backend that reports non-atomic batch support.
        pub fn non_atomic() -> Self {
            Self {
                state: Rc::new(RefCell::new(TestBackendState::default())),
                atomic: false,
            }
        }

        /// Directly inserts a key-value pair (bypassing `apply_batch`).
        pub fn set(&self, key: Vec<u8>, value: Vec<u8>) {
            self.state.borrow_mut().kv.insert(key, value);
        }

        /// Returns true if the store contains `key`.
        pub fn contains_key(&self, key: &[u8]) -> bool {
            self.state.borrow().kv.contains_key(key)
        }

        /// Returns a clone of the value for `key`, if present.
        pub fn get_value(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.state.borrow().kv.get(key).cloned()
        }

        /// Injects a failure when the internal `get` call counter reaches
        /// `call_no` (1-indexed).
        ///
        /// Overwrites any previously enqueued get faults. Use
        /// [`enqueue_get_fault`](Self::enqueue_get_fault) for additive semantics.
        pub fn set_fail_on_get_call(&self, call_no: usize) {
            let mut state = self.state.borrow_mut();
            assert!(
                call_no > state.get_fault_count,
                "call_no={call_no} has already passed; next get call is {}",
                state.get_fault_count + 1
            );
            state.get_faults.clear();
            state.get_faults.push((call_no, GetFault::Fail));
        }

        /// Clears any previously enqueued get faults.
        pub fn clear_fail_on_get_call(&self) {
            self.state.borrow_mut().get_faults.clear();
        }

        /// Enables phase-annotated operation logging.
        pub fn enable_phase_logging(&self) {
            self.state.borrow_mut().phase_logging = true;
        }

        /// Returns a clone of the phase-annotated operation log.
        pub fn op_log(&self) -> Vec<SimBackendOp> {
            self.state.borrow().op_log.clone()
        }

        /// Installs a content-aware batch fault queue.
        ///
        /// Each trigger is consumed in order: `Any` fires on the next
        /// `apply_batch` regardless of content; `KeyPrefix` fires only when
        /// at least one op key starts with the given prefix. Non-matching
        /// batches skip the current trigger without advancing the index.
        pub fn set_batch_faults(&self, faults: Vec<BatchFaultTrigger>) {
            let mut state = self.state.borrow_mut();
            state.batch_faults = faults;
            state.batch_fault_idx = 0;
        }

        /// Returns the current index into the batch fault queue.
        pub fn batch_fault_index(&self) -> usize {
            self.state.borrow().batch_fault_idx
        }

        /// Enqueues a fault on the Nth `get` call (1-indexed).
        ///
        /// Each call number may have at most one fault; duplicates panic.
        pub fn enqueue_get_fault(&self, call_no: usize, fault: GetFault) {
            let mut state = self.state.borrow_mut();
            assert!(
                call_no > state.get_fault_count,
                "call_no={call_no} has already passed; next get call is {}",
                state.get_fault_count + 1
            );
            assert!(
                !state.get_faults.iter().any(|(n, _)| *n == call_no),
                "duplicate get fault at call_no={call_no}; only the first would fire"
            );
            state.get_faults.push((call_no, fault));
        }

        /// Enqueues a fault on the Nth `multi_get` call (1-indexed).
        ///
        /// Each call number may have at most one fault; duplicates panic.
        pub fn enqueue_multi_get_fault(&self, call_no: usize, fault: GetFault) {
            let state = self.state.borrow();
            assert!(
                call_no > state.multi_get_fault_count,
                "call_no={call_no} has already passed; next multi_get call is {}",
                state.multi_get_fault_count + 1
            );
            assert!(
                !state.multi_get_faults.iter().any(|(n, _)| *n == call_no),
                "duplicate multi_get fault at call_no={call_no}; only the first would fire"
            );
            assert!(
                !state.multi_get_truncate,
                "enqueue_multi_get_fault and set_multi_get_truncate are mutually exclusive; \
                 faults silently suppress the length-mismatch simulation"
            );
            drop(state);
            self.state
                .borrow_mut()
                .multi_get_faults
                .push((call_no, fault));
        }

        /// Configures `multi_get` to return one fewer result than requested.
        pub fn set_multi_get_truncate(&self, truncate: bool) {
            let state = self.state.borrow();
            assert!(
                state.multi_get_faults.is_empty() || !truncate,
                "set_multi_get_truncate and enqueue_multi_get_fault are mutually exclusive; \
                 faults silently suppress the length-mismatch simulation"
            );
            drop(state);
            self.state.borrow_mut().multi_get_truncate = truncate;
        }

        /// Returns recorded batches from *successful* `apply_batch` calls.
        /// Faulted calls do not appear here. Use [`batch_call_count`](Self::batch_call_count)
        /// for the total call count including faulted calls.
        pub fn batches(&self) -> Vec<Vec<GitPersistenceOp>> {
            self.state.borrow().batches.clone()
        }

        /// Returns the total number of `apply_batch` calls so far, including
        /// calls rejected by fault injection.
        pub fn batch_call_count(&self) -> usize {
            self.state.borrow().batch_call_count
        }
    }

    impl GitPersistenceBackend for TestBackend {
        type Error = TestBackendError;

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            let mut state = self.state.borrow_mut();
            state.get_fault_count += 1;
            let count = state.get_fault_count;
            let fault = if let Some(pos) = state.get_faults.iter().position(|(n, _)| *n == count) {
                Some(state.get_faults.remove(pos).1)
            } else {
                None
            };
            let value = state.kv.get(key).cloned();
            drop(state);

            match fault {
                Some(fault) => apply_get_fault_value(value, fault),
                None => Ok(value),
            }
        }

        /// Injected failures are all-or-nothing: a failing call returns `Err`
        /// without applying any ops. Partial batch application (where some ops
        /// land before the failure) is not modeled.
        fn apply_batch(&self, ops: &[GitPersistenceOp]) -> Result<(), Self::Error> {
            let mut state = self.state.borrow_mut();
            state.batch_call_count += 1;

            // Content-aware fault queue: fires when the batch contains a key
            // matching the current trigger's prefix.
            if let Some(&trigger) = state.batch_faults.get(state.batch_fault_idx) {
                let triggered = match trigger {
                    BatchFaultTrigger::Any => true,
                    BatchFaultTrigger::KeyPrefix(prefix) => {
                        ops.iter().any(|op| op_key(op).starts_with(prefix))
                    }
                };
                if triggered {
                    state.batch_fault_idx += 1;
                    return Err(TestBackendError {
                        message: "injected batch failure (content-aware)",
                    });
                }
            }

            if state.phase_logging {
                for op in ops {
                    state.op_log.push(SimBackendOp::new(op.clone()));
                }
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

        /// `get` and `multi_get` maintain independent fault queues and call
        /// counters. A fault enqueued via `enqueue_get_fault` never fires
        /// during `multi_get`, and vice versa.
        ///
        /// Unlike the trait default (which delegates to `get()` N times),
        /// this override processes the entire key set as a single operation,
        /// so a `GetFault::Fail` rejects all keys at once.
        fn multi_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
            let mut state = self.state.borrow_mut();
            state.multi_get_fault_count += 1;
            let count = state.multi_get_fault_count;
            let fault =
                if let Some(pos) = state.multi_get_faults.iter().position(|(n, _)| *n == count) {
                    Some(state.multi_get_faults.remove(pos).1)
                } else {
                    None
                };
            let values: Vec<_> = keys
                .iter()
                .map(|key| state.kv.get(key.as_slice()).cloned())
                .collect();

            // Length-mismatch simulation: returns one fewer result than requested.
            if state.multi_get_truncate && !values.is_empty() && fault.is_none() {
                return Ok(values[..values.len() - 1].to_vec());
            }

            drop(state);

            match fault {
                Some(fault) => apply_get_fault_values(values, fault),
                None => Ok(values),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use gossip_contracts::{
        connector::git::RepoKey,
        identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId},
        persistence::CheckpointBoundaryKind,
    };

    use super::test_support::*;
    use super::*;
    use scanner_git::NS_REF_WATERMARK;

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

    fn put_op(key: &[u8], value: &[u8]) -> GitPersistenceOp {
        GitPersistenceOp::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        }
    }

    fn delete_op(key: &[u8]) -> GitPersistenceOp {
        GitPersistenceOp::Delete { key: key.to_vec() }
    }

    fn sim_oid(byte: u8) -> OidBytes {
        OidBytes::sha1([byte; 20])
    }

    #[test]
    fn sim_backend_put_get_roundtrip() {
        let backend = TestBackend::non_atomic();
        let key = b"bc\0blob".to_vec();
        let value = vec![0x10, 0x20, 0x30];

        backend
            .apply_batch(&[put_op(&key, &value)])
            .expect("put must succeed");

        assert_eq!(
            backend.get(&key).expect("get must succeed"),
            Some(value.clone())
        );
        assert_eq!(
            backend
                .multi_get(std::slice::from_ref(&key))
                .expect("multi_get must succeed"),
            vec![Some(value)]
        );
    }

    #[test]
    fn sim_backend_delete_removes_key() {
        let backend = TestBackend::atomic();
        let key = b"fn\0finding".to_vec();
        backend.set(key.clone(), vec![0xAB]);

        backend
            .apply_batch(&[delete_op(&key)])
            .expect("delete must succeed");

        assert!(!backend.contains_key(&key));
        assert_eq!(backend.get(&key).expect("get must succeed"), None);
    }

    #[test]
    fn sim_backend_batch_fault_any_fires_on_first_call() {
        let backend = TestBackend::non_atomic();
        backend.enable_phase_logging();
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);

        let err = backend
            .apply_batch(&[put_op(b"bc\0blob", &[0xAA])])
            .expect_err("the queued Any fault must fail the next batch");

        assert!(err.to_string().contains("injected batch failure"));
        assert_eq!(backend.batch_fault_index(), 1);
        assert!(backend.get_value(b"bc\0blob").is_none());
        assert!(backend.op_log().is_empty());
    }

    #[test]
    fn sim_backend_batch_fault_key_prefix_fires_on_matching_batch() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(b"rw")]);

        let err = backend
            .apply_batch(&[put_op(b"rw\0wm", &[0xBB])])
            .expect_err("the queued prefix fault must fail the matching batch");

        assert!(err.to_string().contains("injected batch failure"));
        assert_eq!(backend.batch_fault_index(), 1);
        assert!(backend.get_value(b"rw\0wm").is_none());
    }

    #[test]
    fn sim_backend_batch_fault_key_prefix_skips_non_matching_batch() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(b"rw")]);

        backend
            .apply_batch(&[put_op(b"bc\0blob", &[0x01])])
            .expect("non-matching batch must succeed");

        assert_eq!(backend.batch_fault_index(), 0);
        assert_eq!(backend.get_value(b"bc\0blob"), Some(vec![0x01]));
    }

    #[test]
    fn sim_backend_get_truncates_single_value() {
        let backend = TestBackend::atomic();
        let key = b"bc\0blob".to_vec();
        backend.set(key.clone(), vec![0x11, 0x22, 0x33]);
        backend.enqueue_get_fault(1, GetFault::Truncate { max_len: 2 });

        assert_eq!(
            backend.get(&key).expect("get must truncate"),
            Some(vec![0x11, 0x22])
        );
    }

    #[test]
    fn sim_backend_multi_get_truncates_values() {
        let backend = TestBackend::atomic();
        let key = b"rw\0wm".to_vec();
        backend.set(key.clone(), vec![0x44, 0x55, 0x66]);
        backend.enqueue_multi_get_fault(1, GetFault::Truncate { max_len: 1 });

        assert_eq!(
            backend
                .multi_get(std::slice::from_ref(&key))
                .expect("multi_get must truncate"),
            vec![Some(vec![0x44])]
        );
    }

    #[test]
    fn sim_backend_get_fault_returns_error() {
        let backend = TestBackend::atomic();
        let key = b"bc\0blob".to_vec();
        backend.set(key.clone(), vec![0x11]);
        backend.enqueue_get_fault(1, GetFault::Fail);

        let err = backend.get(&key).expect_err("get must fail");
        assert!(err.to_string().contains("injected get failure"));
    }

    #[test]
    fn sim_backend_multi_get_fault_returns_error() {
        let backend = TestBackend::atomic();
        let key = b"rw\0wm".to_vec();
        backend.set(key.clone(), vec![0x22]);
        backend.enqueue_multi_get_fault(1, GetFault::Fail);

        let err = backend
            .multi_get(std::slice::from_ref(&key))
            .expect_err("multi_get must fail");
        assert!(err.to_string().contains("injected get failure"));
    }

    #[test]
    fn sim_backend_log_annotates_phases() {
        let backend = TestBackend::non_atomic();
        backend.enable_phase_logging();
        let scope_key = build_seen_scope_key(42, &[0x42; 32]);
        let staging_key = build_seen_staging_key(42, &[0x42; 32]);

        backend
            .apply_batch(&[
                put_op(b"bc\0blob", &[0x01]),
                put_op(b"fn\0finding", &[0x02]),
                put_op(&scope_key, &[0x03]),
                delete_op(&staging_key),
                put_op(b"rw\0wm", &[0x04]),
            ])
            .expect("batch must succeed");

        let phases: Vec<_> = backend
            .op_log()
            .into_iter()
            .map(|entry| entry.ns())
            .collect();
        assert_eq!(
            phases,
            vec![
                KeyNamespace::BlobCtx,
                KeyNamespace::Finding,
                KeyNamespace::SeenScope,
                KeyNamespace::SeenStaging,
                KeyNamespace::Watermark,
            ]
        );
    }

    #[test]
    fn sim_backend_atomic_flag_is_configurable() {
        assert!(TestBackend::atomic().supports_atomic_batches());
        assert!(!TestBackend::non_atomic().supports_atomic_batches());
    }

    #[test]
    fn sim_backend_non_matching_prefix_fault_does_not_advance_index() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![
            BatchFaultTrigger::key_prefix(b"rw"),
            BatchFaultTrigger::any(),
        ]);

        backend
            .apply_batch(&[put_op(b"bc\0blob", &[0x01])])
            .expect("first non-matching batch must succeed");
        backend
            .apply_batch(&[put_op(b"fn\0finding", &[0x02])])
            .expect("second non-matching batch must succeed");
        assert_eq!(backend.batch_fault_index(), 0);

        backend
            .apply_batch(&[put_op(b"rw\0wm", &[0x03])])
            .expect_err("matching prefix must consume the first queued fault");
        assert_eq!(backend.batch_fault_index(), 1);

        backend
            .apply_batch(&[put_op(b"bc\0next", &[0x04])])
            .expect_err("the next queued Any fault must now fire");
        assert_eq!(backend.batch_fault_index(), 2);
    }

    #[test]
    fn sim_backend_multiple_faults_fire_in_sequence() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![
            BatchFaultTrigger::any(),
            BatchFaultTrigger::key_prefix(b"rw"),
        ]);

        backend
            .apply_batch(&[put_op(b"bc\0blob", &[0x01])])
            .expect_err("the first Any fault must fire");
        assert_eq!(backend.batch_fault_index(), 1);

        backend
            .apply_batch(&[put_op(b"fn\0finding", &[0x02])])
            .expect("the queued prefix fault must ignore non-matching batches");
        assert_eq!(backend.batch_fault_index(), 1);

        backend
            .apply_batch(&[put_op(b"rw\0wm", &[0x03])])
            .expect_err("the queued prefix fault must fire on the matching batch");
        assert_eq!(backend.batch_fault_index(), 2);
    }

    #[test]
    fn sim_backend_exhausted_faults_default_to_success() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);

        backend
            .apply_batch(&[put_op(b"bc\0blob", &[0x01])])
            .expect_err("the only queued fault must fire once");
        assert_eq!(backend.batch_fault_index(), 1);

        backend
            .apply_batch(&[put_op(b"bc\0blob", &[0x02])])
            .expect("batches must succeed after the fault plan is exhausted");
        assert_eq!(backend.get_value(b"bc\0blob"), Some(vec![0x02]));
    }

    #[test]
    fn sim_backend_works_with_git_persistence_adapter() {
        let backend = TestBackend::non_atomic();
        backend.enable_phase_logging();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 42, [0x42; 32]);
        let oid = sim_oid(0xAB);

        adapter
            .persist_seen_delta(&[oid])
            .expect("stage seen delta");
        adapter
            .commit_finalize(&finalize_output(FinalizeOutcome::Complete))
            .expect("complete finalize must succeed");

        assert_eq!(
            adapter.batch_check_seen(&[oid]).expect("seen check"),
            vec![true]
        );
        assert!(
            !backend.contains_key(&build_seen_staging_key(42, &[0x42; 32])),
            "complete finalize must remove the staging key"
        );
        assert_eq!(backend.get_value(b"rw\0wm"), Some(vec![0xBB]));

        let namespaces: Vec<_> = backend
            .op_log()
            .into_iter()
            .map(|entry| entry.ns())
            .collect();
        assert!(namespaces.contains(&KeyNamespace::BlobCtx));

        // Crash-safety invariant: seen-scope writes must precede watermark
        // writes so that a crash between the two batches never exposes
        // watermarks without corresponding data.
        let scope_pos = namespaces
            .iter()
            .position(|ns| *ns == KeyNamespace::SeenScope)
            .expect("seen-scope write must appear in log");
        let watermark_pos = namespaces
            .iter()
            .position(|ns| *ns == KeyNamespace::Watermark)
            .expect("watermark write must appear in log");
        assert!(
            scope_pos < watermark_pos,
            "seen-scope must be written before watermarks for crash safety; \
             scope at {scope_pos}, watermark at {watermark_pos}"
        );
    }

    #[test]
    fn adapter_non_atomic_watermark_fault_preserves_data() {
        let backend = TestBackend::non_atomic();
        backend.enable_phase_logging();
        // KeyPrefix targeting the watermark namespace skips the first-phase
        // batch (data+seen) and fires on the watermark batch.
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(
            scanner_git::NS_REF_WATERMARK.as_slice(),
        )]);

        let adapter = GitPersistenceAdapter::new(backend.clone(), 50, [0x50; 32]);
        let err = adapter
            .commit_finalize(&finalize_output(FinalizeOutcome::Complete))
            .expect_err("watermark batch fault must propagate");

        assert!(format!("{err}").contains("injected batch failure"));
        // Data ops must have landed (first-phase batch succeeded).
        assert_eq!(
            backend.get_value(b"bc\0blob").as_deref(),
            Some(&[0xAA][..]),
            "data writes must survive when only the watermark batch fails"
        );
        // Watermarks must NOT have landed.
        assert!(
            backend.get_value(b"rw\0wm").is_none(),
            "watermarks must remain absent when the watermark batch fails"
        );
        // Phase log must contain data phases but not watermark.
        let namespaces: Vec<_> = backend.op_log().iter().map(|e| e.ns()).collect();
        assert!(namespaces.contains(&KeyNamespace::BlobCtx));
        assert!(
            !namespaces.contains(&KeyNamespace::Watermark),
            "watermark ops must not appear in the log when the batch was rejected"
        );
    }

    #[test]
    fn adapter_non_atomic_first_batch_fault_blocks_everything() {
        let backend = TestBackend::non_atomic();
        backend.enable_phase_logging();
        // Any fault fires on the very first apply_batch (data+seen phase).
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);

        let adapter = GitPersistenceAdapter::new(backend.clone(), 51, [0x51; 32]);
        let err = adapter
            .commit_finalize(&finalize_output(FinalizeOutcome::Complete))
            .expect_err("first-phase fault must propagate");

        assert!(format!("{err}").contains("injected batch failure"));
        // Nothing must have landed.
        assert!(
            backend.get_value(b"bc\0blob").is_none(),
            "data writes must not land when the first-phase batch fails"
        );
        assert!(
            backend.get_value(b"rw\0wm").is_none(),
            "watermarks must not land when the first-phase batch fails"
        );
        assert!(
            backend.op_log().is_empty(),
            "operation log must be empty when the first batch was rejected"
        );
    }

    #[test]
    fn adapter_atomic_single_batch_all_phases() {
        let backend = TestBackend::atomic();
        backend.enable_phase_logging();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 52, [0x52; 32]);
        let oid = sim_oid(0xCC);

        adapter
            .persist_seen_delta(&[oid])
            .expect("stage seen delta");
        adapter
            .commit_finalize(&finalize_output(FinalizeOutcome::Complete))
            .expect("atomic finalize must succeed");

        // Atomic backend: staging persist is 1 batch, finalize is 1 batch.
        assert_eq!(
            backend.batches().len(),
            2,
            "atomic backend: staging + finalize = 2 batches"
        );

        // The finalize batch must contain all phases in a single apply_batch.
        let namespaces: Vec<_> = backend.op_log().iter().map(|e| e.ns()).collect();
        assert!(
            namespaces.contains(&KeyNamespace::BlobCtx),
            "finalize batch must contain blob context ops"
        );
        assert!(
            namespaces.contains(&KeyNamespace::SeenScope),
            "finalize batch must contain seen-scope ops"
        );
        assert!(
            namespaces.contains(&KeyNamespace::Watermark),
            "finalize batch must contain watermark ops"
        );

        // Data integrity.
        assert_eq!(
            adapter.batch_check_seen(&[oid]).expect("seen check"),
            vec![true]
        );
        assert_eq!(backend.get_value(b"rw\0wm").as_deref(), Some(&[0xBB][..]));
    }

    #[test]
    fn batch_fault_prefix_rejects_entire_batch_on_single_match() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(b"rw")]);

        // Batch contains one matching and one non-matching op. The entire
        // batch must be rejected because `any` op key matches the prefix.
        let err = backend
            .apply_batch(&[put_op(b"bc\0blob", &[0x01]), put_op(b"rw\0wm", &[0x02])])
            .expect_err("prefix match on one key rejects the entire batch");

        assert!(err.to_string().contains("injected batch failure"));
        // Neither op should have landed.
        assert!(
            backend.get_value(b"bc\0blob").is_none(),
            "non-matching op must also be rejected when the batch fails"
        );
        assert!(
            backend.get_value(b"rw\0wm").is_none(),
            "matching op must not land when the batch is rejected"
        );
    }

    #[test]
    fn sim_backend_get_fault_skips_earlier_calls_and_fires_on_target() {
        let backend = TestBackend::non_atomic();
        let key = b"bc\0blob".to_vec();
        backend.set(key.clone(), vec![0x11, 0x22, 0x33]);
        backend.enqueue_get_fault(2, GetFault::Truncate { max_len: 1 });

        // First get succeeds normally (call_no=2 targets the second call).
        assert_eq!(
            backend.get(&key).expect("first get must succeed"),
            Some(vec![0x11, 0x22, 0x33])
        );

        // Second get fires the fault.
        assert_eq!(
            backend.get(&key).expect("second get must truncate"),
            Some(vec![0x11])
        );

        // Third get succeeds normally (fault is one-shot).
        assert_eq!(
            backend.get(&key).expect("third get must succeed"),
            Some(vec![0x11, 0x22, 0x33])
        );
    }

    #[test]
    fn sim_backend_empty_batch_with_any_fault_still_fires() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);

        backend
            .apply_batch(&[])
            .expect_err("Any fault fires even on an empty batch");
        assert_eq!(backend.batch_fault_index(), 1);
    }

    #[test]
    fn sim_backend_empty_batch_with_key_prefix_fault_does_not_fire() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(b"rw")]);

        backend
            .apply_batch(&[])
            .expect("KeyPrefix fault does not match an empty batch");
        assert_eq!(backend.batch_fault_index(), 0);
    }

    #[test]
    fn sim_backend_get_absent_key_returns_none() {
        let backend = TestBackend::non_atomic();
        assert_eq!(backend.get(b"absent").expect("get must succeed"), None);
    }

    #[test]
    fn sim_backend_multi_get_mixed_present_and_absent() {
        let backend = TestBackend::non_atomic();
        backend.set(b"bc\0present".to_vec(), vec![0x01]);

        let results = backend
            .multi_get(&[b"bc\0present".to_vec(), b"bc\0absent".to_vec()])
            .expect("multi_get must succeed");
        assert_eq!(results, vec![Some(vec![0x01]), None]);
    }

    #[test]
    fn sim_backend_set_batch_faults_replaces_queue_and_resets_index() {
        let backend = TestBackend::non_atomic();
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);

        backend
            .apply_batch(&[put_op(b"bc\0a", &[1])])
            .expect_err("first fault fires");
        assert_eq!(backend.batch_fault_index(), 1);

        // Overwrite with a new queue; index must reset.
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(b"fn")]);
        assert_eq!(backend.batch_fault_index(), 0);

        backend
            .apply_batch(&[put_op(b"bc\0b", &[2])])
            .expect("non-matching prefix passes");
        assert_eq!(backend.batch_fault_index(), 0);
    }

    #[test]
    fn sim_backend_delete_nonexistent_key_is_noop() {
        let backend = TestBackend::non_atomic();
        backend.enable_phase_logging();
        backend
            .apply_batch(&[delete_op(b"bc\0missing")])
            .expect("delete of absent key must succeed");
        assert_eq!(backend.op_log().len(), 1, "delete is still logged");
    }

    #[test]
    fn adapter_atomic_fault_during_finalize_blocks_everything() {
        let backend = TestBackend::atomic();
        backend.enable_phase_logging();

        let adapter = GitPersistenceAdapter::new(backend.clone(), 60, [0x60; 32]);
        let oid = sim_oid(0xDD);

        adapter
            .persist_seen_delta(&[oid])
            .expect("stage seen delta");

        // Install fault after staging so it targets the finalize batch.
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);

        let err = adapter
            .commit_finalize(&finalize_output(FinalizeOutcome::Complete))
            .expect_err("atomic finalize fault must propagate");

        assert!(format!("{err}").contains("injected batch failure"));
        // Atomic path: single batch for all phases. No finalize data must land.
        assert!(
            backend.get_value(b"bc\0blob").is_none(),
            "data must not land when the atomic finalize batch fails"
        );
        assert!(
            backend.get_value(b"rw\0wm").is_none(),
            "watermarks must not land when the atomic finalize batch fails"
        );
        // The op log may contain staging ops from persist_seen_delta, but
        // must not contain any finalize-phase ops.
        let namespaces: Vec<_> = backend.op_log().iter().map(|e| e.ns()).collect();
        assert!(
            !namespaces.contains(&KeyNamespace::BlobCtx),
            "blob-ctx ops must not appear when the finalize batch was rejected"
        );
        assert!(
            !namespaces.contains(&KeyNamespace::Watermark),
            "watermark ops must not appear when the finalize batch was rejected"
        );
    }

    #[test]
    fn sim_backend_clear_get_faults_preserves_counter() {
        let backend = TestBackend::non_atomic();
        let key = b"bc\0blob".to_vec();
        backend.set(key.clone(), vec![0x11, 0x22]);

        // Fire a fault on the first get call.
        backend.enqueue_get_fault(1, GetFault::Fail);
        backend.get(&key).expect_err("first get must fail");

        // Clear and re-enqueue. The counter is now at 1, so targeting
        // call_no=2 should fire on the next get.
        backend.clear_fail_on_get_call();
        backend.enqueue_get_fault(2, GetFault::Truncate { max_len: 1 });

        assert_eq!(
            backend.get(&key).expect("second get must truncate"),
            Some(vec![0x11]),
            "fault at call_no=2 fires because the counter kept incrementing past clear"
        );

        // Third call: no faults remain.
        assert_eq!(
            backend.get(&key).expect("third get must succeed"),
            Some(vec![0x11, 0x22])
        );
    }

    #[test]
    fn sim_backend_get_truncate_on_absent_key_returns_none() {
        let backend = TestBackend::non_atomic();
        backend.enqueue_get_fault(1, GetFault::Truncate { max_len: 0 });

        // Truncation on an absent key is a no-op: None stays None.
        assert_eq!(
            backend.get(b"bc\0absent").expect("get must succeed"),
            None,
            "truncation of an absent key must return None, not Some(vec![])"
        );
    }

    #[test]
    fn sim_backend_phase_logging_disabled_by_default() {
        let backend = TestBackend::non_atomic();
        backend
            .apply_batch(&[put_op(b"bc\0blob", &[0x01])])
            .expect("batch must succeed");

        assert!(
            backend.op_log().is_empty(),
            "op_log must stay empty when phase logging is not enabled"
        );
    }

    #[test]
    fn sim_adapter_batch_fault_during_commit_finalize() {
        let backend = TestBackend::non_atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 42, [0x42; 32]);

        // Inject a fault that fires on watermark-prefixed batches.
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(b"rw")]);

        let result = adapter.commit_finalize(&finalize_output(FinalizeOutcome::Complete));
        assert!(
            result.is_err(),
            "watermark fault must propagate through adapter"
        );

        // Data-phase ops should have landed (non-atomic: data batch precedes
        // watermark batch, and only the watermark batch was faulted).
        assert_eq!(backend.get_value(b"bc\0blob"), Some(vec![0xAA]));
        // Watermark must NOT have landed.
        assert!(
            backend.get_value(b"rw\0wm").is_none(),
            "watermark must not land when its batch is faulted"
        );
    }

    #[test]
    fn sim_adapter_cold_cache_batch_check_seen() {
        let backend = TestBackend::non_atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 42, [0x42; 32]);
        let oid = sim_oid(0xAB);

        // Cold cache: no prior persist_seen_delta or finalize.
        let results = adapter
            .batch_check_seen(&[oid])
            .expect("cold-cache seen check must succeed");
        assert_eq!(results, vec![false], "unseen OID must return false");
    }

    #[test]
    fn load_watermarks_preserves_ref_order() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 7, [0x55; 32]);
        let start_set_id = [0x66; 32];
        let ref_a = b"refs/heads/main".as_slice();
        let ref_b = b"refs/tags/v1".as_slice();

        let value_a = scanner_git::encode_ref_watermark_value(
            &OidBytes::sha1([0x11; 20]),
            NonZeroU32::new(11).unwrap(),
        );
        let value_b = scanner_git::encode_ref_watermark_value(
            &OidBytes::sha1([0x22; 20]),
            NonZeroU32::new(22).unwrap(),
        );
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
                Some(RefWatermark {
                    oid: OidBytes::sha1([0x22; 20]),
                    generation: NonZeroU32::new(22).unwrap(),
                }),
                None,
                Some(RefWatermark {
                    oid: OidBytes::sha1([0x11; 20]),
                    generation: NonZeroU32::new(11).unwrap(),
                }),
            ]
        );
    }

    #[test]
    fn load_watermarks_rejects_oid_only_values() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 7, [0x77; 32]);
        let start_set_id = [0x88; 32];
        let ref_name = b"refs/heads/main".as_slice();
        let oid = OidBytes::sha1([0x33; 20]);
        // OID-only payload (no generation trailer).
        let mut oid_only = vec![oid.len()];
        oid_only.extend_from_slice(oid.as_slice());
        backend.set(
            build_ref_wm_key(7, &[0x77; 32], &start_set_id, ref_name),
            oid_only,
        );

        // The decoder rejects OID-only payloads as malformed, which the
        // adapter surfaces as an error (invalid watermark encoding).
        let result = adapter.load_watermarks(7, [0x77; 32], start_set_id, &[ref_name]);
        assert!(
            result.is_err(),
            "OID-only watermark values must be rejected as malformed"
        );
    }

    #[test]
    fn load_watermarks_rejects_identity_mismatch() {
        use std::error::Error;

        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 7, [0x55; 32]);

        let err = adapter
            .load_watermarks(99, [0x55; 32], [0x66; 32], &[b"refs/heads/main"])
            .expect_err("mismatched repo_id must fail");
        assert!(matches!(err, RepoOpenError::Io(_)));
        let source_msg = err.source().expect("source").to_string();
        assert!(
            source_msg.contains("identity mismatch"),
            "source should mention identity mismatch, got: {source_msg}"
        );

        let err = adapter
            .load_watermarks(7, [0xAA; 32], [0x66; 32], &[b"refs/heads/main"])
            .expect_err("mismatched policy_hash must fail");
        assert!(matches!(err, RepoOpenError::Io(_)));
        let source_msg = err.source().expect("source").to_string();
        assert!(
            source_msg.contains("identity mismatch"),
            "source should mention identity mismatch, got: {source_msg}"
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
                    FindingsCommitReceipt::new(0, 0, 0),
                    DoneLedgerCommitReceipt::new(1, 1, 0),
                )
                .expect("checkpoint input")
                .is_none(),
            "partial finalize must not yield outer progress"
        );
    }

    #[test]
    fn partial_finalize_commits_data_ops_seen_deltas_but_discards_staging() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 30, [0x30; 32]);
        let staged_oid = OidBytes::sha1([0x11; 20]);
        let data_oid = OidBytes::sha1([0x22; 20]);

        // Stage one OID via the spill path.
        adapter.persist_seen_delta(&[staged_oid]).expect("stage");

        // Partial finalize with a data_ops seen delta containing a different OID.
        let delta = SeenBitmapDelta::from_oids(&[data_oid]).expect("delta");
        let scope_key = build_seen_scope_key(30, &[0x30; 32]);
        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: vec![WriteOp {
                    key: scope_key,
                    value: delta.serialize(),
                }],
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Partial { skipped_count: 1 },
                stats: Default::default(),
            })
            .expect("partial finalize");

        // data_ops OIDs are committed (they were genuinely scanned).
        assert_eq!(
            adapter.batch_check_seen(&[data_oid]).expect("data oid"),
            vec![true],
            "data_ops seen deltas are committed even on partial finalize"
        );
        // Staging OIDs are discarded (may include blobs from skipped candidates).
        assert_eq!(
            adapter.batch_check_seen(&[staged_oid]).expect("staged oid"),
            vec![false],
            "staging seen deltas are discarded on partial finalize"
        );
    }

    #[test]
    fn multiple_spills_accumulate_in_staging_before_finalize() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 22, [0x22; 32]);
        let oid_a = OidBytes::sha1([0x11; 20]);
        let oid_b = OidBytes::sha1([0x22; 20]);

        adapter.persist_seen_delta(&[oid_a]).expect("first spill");
        adapter.persist_seen_delta(&[oid_b]).expect("second spill");

        // Neither OID is visible before finalize.
        assert_eq!(
            adapter
                .batch_check_seen(&[oid_a, oid_b])
                .expect("check before finalize"),
            vec![false, false]
        );

        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect("complete finalize");

        // Both OIDs from separate spills must be visible after finalize.
        assert_eq!(
            adapter
                .batch_check_seen(&[oid_a, oid_b])
                .expect("check after finalize"),
            vec![true, true],
            "sequential spill deltas must accumulate and survive finalize"
        );
    }

    #[test]
    fn complete_finalize_merges_staging_and_data_ops_seen_deltas() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 20, [0x20; 32]);
        let staged_oid = OidBytes::sha1([0x11; 20]);
        let delta_oid = OidBytes::sha1([0x22; 20]);

        // Stage one OID via the spill path.
        adapter
            .persist_seen_delta(&[staged_oid])
            .expect("stage seen delta");

        // Finalize with a data_ops seen delta containing a different OID.
        let delta = SeenBitmapDelta::from_oids(&[delta_oid]).expect("build finalize delta");
        let scope_key = build_seen_scope_key(20, &[0x20; 32]);
        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: vec![WriteOp {
                    key: scope_key,
                    value: delta.serialize(),
                }],
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect("complete finalize");

        // Both OIDs — from staging and from the finalize delta — must be
        // visible after the merge.
        assert_eq!(
            adapter
                .batch_check_seen(&[staged_oid, delta_oid])
                .expect("batch check after merge"),
            vec![true, true],
            "complete finalize must merge staging and data_ops seen deltas"
        );
    }

    #[test]
    fn complete_finalize_yields_repo_frontier_receipt_and_checkpoint_input() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 11, [0xB0; 32]);

        let receipt = adapter
            .repo_frontier_receipt(
                write_context(),
                7,
                &repo_key(),
                FinalizeOutcome::Complete,
                FindingsCommitReceipt::new(0, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
            )
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
                FindingsCommitReceipt::new(0, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
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
            .repo_frontier_receipt(
                write_context(),
                3,
                &repo_key(),
                FinalizeOutcome::Complete,
                FindingsCommitReceipt::new(0, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
            )
            .expect("first receipt");
        let second = adapter
            .repo_frontier_receipt(
                write_context(),
                3,
                &repo_key(),
                FinalizeOutcome::Complete,
                FindingsCommitReceipt::new(0, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
            )
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
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(&NS_REF_WATERMARK)]);
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
        // Batch 1: persist_seen_delta staging write
        // Batch 2: commit_finalize first-phase (data+seen scope)
        // Batch 3: commit_finalize staging delete
        // Batch 4: commit_finalize watermark phase
        // Target the watermark batch to prove the seen cache survives.
        backend.set_batch_faults(vec![BatchFaultTrigger::key_prefix(&NS_REF_WATERMARK)]);
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

    #[test]
    fn non_atomic_partial_finalize_does_not_leak_staging_into_later_complete() {
        let backend = TestBackend::non_atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 25, [0x25; 32]);
        let oid = OidBytes::sha1([0xCC; 20]);

        // Stage an OID via the spill path.
        adapter.persist_seen_delta(&[oid]).expect("stage");

        // Partial finalize discards staging. On non-atomic backends, the
        // staging Delete is in the same batch as data ops so a batch
        // failure rolls back both together.
        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Partial { skipped_count: 1 },
                stats: Default::default(),
            })
            .expect("partial finalize");

        // Staging must be gone — a subsequent complete finalize must not
        // find stale staging to fold into the seen scope.
        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect("complete finalize");

        assert_eq!(
            adapter.batch_check_seen(&[oid]).expect("check"),
            vec![false],
            "partial-discarded staging must not leak into a later complete finalize"
        );
    }

    #[test]
    fn non_atomic_first_phase_failure_leaves_seen_cache_unchanged() {
        let backend = TestBackend::non_atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 23, [0x23; 32]);
        let oid = OidBytes::sha1([0x77; 20]);

        adapter
            .persist_seen_delta(&[oid])
            .expect("stage seen delta");

        // Fail the first apply_batch inside commit_finalize (data/seen
        // phase). The fault queue fires on the next apply_batch call.
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);
        let _ = adapter
            .commit_finalize(&finalize_output(FinalizeOutcome::Complete))
            .expect_err("first-phase batch should fail");

        // The seen cache must not reflect the failed finalize.
        assert_eq!(
            adapter
                .batch_check_seen(&[oid])
                .expect("cache should not reflect failed first phase"),
            vec![false],
            "first-phase failure must not update the seen cache"
        );
    }

    #[test]
    fn batch_check_seen_propagates_backend_get_failure() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 21, [0x21; 32]);

        // Fail the first get so the seen-store load cannot read the scope key.
        backend.set_fail_on_get_call(1);
        let err = adapter
            .batch_check_seen(&[OidBytes::sha1([0x11; 20])])
            .expect_err("backend get failure should propagate through batch_check_seen");
        assert!(
            format!("{err}").contains("seen-store initialization failed"),
            "error should mention seen-store init, got: {err}"
        );
    }

    #[test]
    fn persist_seen_delta_returns_spill_error_on_backend_get_failure() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 16, [0xAA; 32]);

        // Fail the first get (cache is cold, so the first persist reads
        // from backend to seed the staging cache).
        backend.set_fail_on_get_call(1);
        let err = adapter
            .persist_seen_delta(&[OidBytes::sha1([0x77; 20])])
            .expect_err("backend get failure should propagate");
        assert!(format!("{err}").contains("staging bitmap read failed"));
    }

    #[test]
    fn commit_finalize_returns_persist_error_on_staging_read_failure() {
        let backend = TestBackend::atomic();
        // Pre-populate the staging key in the backend to simulate crash
        // recovery where the staging cache is cold but a prior spill
        // already wrote to the backend.
        let staging_key = build_seen_staging_key(17, &[0xBB; 32]);
        let oid = OidBytes::sha1([0x99; 20]);
        let mut staging_bitmap = RoaringSeenBitmap::new(OidBytes::SHA1_LEN);
        staging_bitmap
            .insert_batch(&[oid])
            .expect("insert into staging bitmap");
        backend.set(staging_key, staging_bitmap.serialize().expect("serialize"));

        // Construct a fresh adapter (no staging cache) and fail the get.
        let adapter = GitPersistenceAdapter::new(backend.clone(), 17, [0xBB; 32]);
        backend.set_fail_on_get_call(1);
        let err = adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect_err("staging read failure should propagate");
        assert!(format!("{err}").contains("staging bitmap read failed"));
    }

    #[test]
    fn load_watermarks_rejects_invalid_watermark_value_encoding() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 18, [0xCC; 32]);
        let start_set_id = [0xDD; 32];
        let ref_name = b"refs/heads/main".as_slice();

        // Seed a key with invalid (too-short) watermark value.
        let key = scanner_git::finalize::build_ref_wm_key(18, &[0xCC; 32], &start_set_id, ref_name);
        backend.set(key, vec![0x01]);

        let err = adapter
            .load_watermarks(18, [0xCC; 32], start_set_id, &[ref_name])
            .expect_err("invalid watermark value should fail");
        let source_msg = std::error::Error::source(&err)
            .map(|s| s.to_string())
            .unwrap_or_default();
        assert!(
            source_msg.contains("invalid watermark value encoding"),
            "expected inner source to mention invalid encoding, got: {source_msg}"
        );
    }

    #[test]
    fn non_atomic_complete_finalize_with_staging_lands_in_four_batches() {
        let backend = TestBackend::non_atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 19, [0xEE; 32]);
        let oid = OidBytes::sha1([0xAA; 20]);

        // Stage a seen delta.
        adapter.persist_seen_delta(&[oid]).expect("stage");

        // Complete finalize with watermark ops.
        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: vec![scanner_git::WriteOp {
                    key: b"rw\0wm".to_vec(),
                    value: vec![0xBB],
                }],
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect("complete finalize");

        // Verify seen OID is visible.
        assert_eq!(
            adapter.batch_check_seen(&[oid]).expect("seen check"),
            vec![true]
        );
        // Verify staging key is cleared.
        assert!(
            !backend.contains_key(&scanner_git::finalize::build_seen_staging_key(
                19,
                &[0xEE; 32]
            )),
            "staging key must be cleared after complete finalize"
        );
        // Verify watermark landed.
        assert_eq!(
            backend.get_value(b"rw\0wm").as_deref(),
            Some(&[0xBB][..]),
            "watermarks must land on complete finalize"
        );
        // Non-atomic: exactly 4 batches (staging persist, first-phase
        // data+seen, staging delete, second-phase watermarks).
        assert_eq!(backend.batches().len(), 4);
    }

    #[test]
    fn failed_staging_write_does_not_pollute_cache_for_finalize() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 24, [0x24; 32]);
        let oid_a = OidBytes::sha1([0xAA; 20]);
        let oid_b = OidBytes::sha1([0xBB; 20]);

        // First persist succeeds — seeds the staging cache with oid_a.
        adapter
            .persist_seen_delta(&[oid_a])
            .expect("first persist should succeed");

        // Second persist fails at the backend write. The cache already
        // has oid_a; if the bug exists, merge_delta adds oid_b to the
        // cached bitmap before the write is attempted, leaving stale
        // OIDs in the cache that were never durably staged.
        backend.set_batch_faults(vec![BatchFaultTrigger::any()]);
        adapter
            .persist_seen_delta(&[oid_b])
            .expect_err("second persist should fail on injected batch failure");

        // Complete finalize: if the cache is polluted, oid_b will be
        // folded into the committed seen scope despite never landing
        // in durable staging.
        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect("complete finalize");

        let results = adapter
            .batch_check_seen(&[oid_a, oid_b])
            .expect("batch check after finalize");
        assert_eq!(
            results,
            vec![true, false],
            "oid_b must not be visible — it was never durably staged"
        );
    }

    #[test]
    fn load_watermarks_rejects_multi_get_result_count_mismatch() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 20, [0xFF; 32]);
        let start_set_id = [0x11; 32];

        backend.set_multi_get_truncate(true);
        let err = adapter
            .load_watermarks(
                20,
                [0xFF; 32],
                start_set_id,
                &[b"refs/heads/a".as_slice(), b"refs/heads/b".as_slice()],
            )
            .expect_err("truncated multi_get should fail");
        let source_msg = std::error::Error::source(&err)
            .map(|s| s.to_string())
            .unwrap_or_default();
        assert!(
            source_msg.contains("returned") && source_msg.contains("results for"),
            "expected inner source to mention count mismatch, got: {source_msg}"
        );
    }

    // ---- git_repo_ovid_inputs tests ----

    #[test]
    fn git_repo_ovid_inputs_different_repo_ids_produce_different_ovid() {
        let a = derive_ovid_hash(&git_repo_ovid_inputs(1));
        let b = derive_ovid_hash(&git_repo_ovid_inputs(2));
        assert_ne!(a, b, "distinct repo IDs must derive distinct OVIDs");
    }

    #[test]
    fn git_repo_ovid_inputs_is_deterministic() {
        let a = derive_ovid_hash(&git_repo_ovid_inputs(42));
        let b = derive_ovid_hash(&git_repo_ovid_inputs(42));
        assert_eq!(a, b, "same repo ID must derive the same OVID");
    }
}
