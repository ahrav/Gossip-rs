//! Finalize + persist builder.
//!
//! Transforms scan results into stably ordered write operations for the
//! persistence layer. This module is a pure builder: it performs no I/O.
//! Callers must write data ops before watermark ops to avoid advancing
//! watermarks past unscanned blobs.
//!
//! # Determinism
//! - Inputs are sorted by OID (blobs) and ref name (refs).
//! - For each blob OID, a single canonical context is selected using the
//!   total order: `commit_id`, `path bytes`, `parent_idx`, `change_kind`,
//!   `ctx_flags`, `cand_flags`.
//! - Findings are deduped by `(start, end, rule_id, norm_hash)` within each
//!   blob OID before persistence.
//! - Determinism is defined over the provided `FinalizeInput`; if upstream
//!   candidate attribution differs, `blob_ctx` values may differ too.
//!
//! # Invariants
//! - `path_arena` and `finding_arena` must cover all references in
//!   `scanned_blobs`.
//! - `skipped_candidate_oids` being non-empty forces a `Partial` outcome and
//!   suppresses watermark ops.
//! - `data_ops` are emitted in namespace order (`bc` < `fn` < `sb`) and sorted
//!   within each namespace for lexicographic stores.
//!
//! # Key Safety
//! - Ref watermark keys are null-terminated to keep prefix scans safe.
//! - Keys use big-endian numeric fields to preserve ordering.
//!
//! # Key namespaces (lexicographic ordering)
//! | Prefix | Namespace     | Description                         |
//! |--------|---------------|-------------------------------------|
//! | `bc\0` | blob_ctx      | Canonical context per scanned blob  |
//! | `fn\0` | finding       | Individual finding records          |
//! | `sb\0` | seen_blob     | Finalize delta for the seen bitmap  |
//! | `ss\0` | seen_staging  | Spill-stage seen bitmap staging         |
//!
//! Watermark keys use the `rw` prefix from `watermark_keys`.

use std::cmp::Ordering;
use std::num::NonZeroU32;

use crate::perf_stats;

use super::byte_arena::ByteArena;
use super::engine_adapter::{
    sort_and_dedupe_findings, FindingKey, FindingSpan, ScannedBlob, ScoredFinding,
};
use super::object_id::OidBytes;
use super::roaring_seen::SeenBitmapDelta;
use super::start_set::StartSetId;
use super::tree_candidate::CandidateContext;
use super::watermark_keys::{encode_ref_watermark_value, NS_REF_WATERMARK};

/// Namespace prefix for blob context keys.
pub const NS_BLOB_CTX: [u8; 3] = *b"bc\0";
/// Namespace prefix for finding keys.
pub const NS_FINDING: [u8; 3] = *b"fn\0";
/// Namespace prefix for the seen bitmap scope key.
pub const NS_SEEN_BLOB: [u8; 3] = *b"sb\0";
/// Namespace prefix for the staging seen bitmap (spill checkpoints).
///
/// Spill-stage deltas are written here and folded into the live `sb\0`
/// key only during `commit_finalize`. On crash, staging keys are orphaned
/// and cleaned up on the next store open.
pub const NS_SEEN_STAGING: [u8; 3] = *b"ss\0";

// Compile-time: verify namespace lexicographic ordering.
const _: () = {
    assert!(NS_BLOB_CTX[0] < NS_FINDING[0]);
    assert!(NS_FINDING[0] < NS_SEEN_BLOB[0]);
};
const _: () = {
    // Staging namespace shares the first byte with the live namespace;
    // ordering is determined by the second byte (`b` < `s`).
    assert!(NS_SEEN_BLOB[1] < NS_SEEN_STAGING[1]);
};

/// A ref entry from the start set.
#[derive(Clone, Debug)]
pub struct RefEntry {
    /// Ref name bytes (e.g., `refs/heads/main`).
    ///
    /// Must not contain NUL bytes (required for prefix-safe keys).
    pub ref_name: Vec<u8>,
    /// Current tip OID for this ref.
    pub tip_oid: OidBytes,
    /// Current tip generation captured by the runner from the commit graph.
    ///
    /// Finalize is a pure builder, so it persists the value it is given
    /// instead of consulting the commit graph directly.
    pub tip_generation: NonZeroU32,
}

/// Input to the finalize builder.
///
/// The builder takes ownership of the collections so it can sort them
/// deterministically. The `path_arena` must contain all `path_ref` entries
/// referenced by `scanned_blobs`, and `finding_arena` must contain all
/// `ScannedBlob.findings` spans. Multiple contexts for the same blob OID are
/// allowed; the builder selects a single canonical context per OID.
pub struct FinalizeInput<'a> {
    /// Repository identifier.
    pub repo_id: u64,
    /// Policy hash (scan configuration identity).
    pub policy_hash: [u8; 32],
    /// Start set identity.
    pub start_set_id: StartSetId,
    /// Refs from the start set. Will be sorted and deduped by name.
    pub refs: Vec<RefEntry>,
    /// Scanned blobs with their contexts and findings.
    /// Will be sorted by OID.
    pub scanned_blobs: Vec<ScannedBlob>,
    /// Shared findings arena referenced by `scanned_blobs`.
    pub finding_arena: &'a [ScoredFinding],
    /// OIDs that were skipped during decode (budget exceeded, corrupt, etc.).
    /// If non-empty, watermarks will NOT be advanced.
    pub skipped_candidate_oids: Vec<OidBytes>,
    /// Arena holding the path bytes referenced by `scanned_blobs`.
    pub path_arena: &'a ByteArena,
}

/// A single key-value write operation for the persistence layer.
///
/// Keys are opaque binary blobs. The finalize builder emits keys in sorted
/// order to enable efficient batch writes in ordered stores.
#[derive(Clone, Debug)]
pub struct WriteOp {
    /// Binary key.
    pub key: Vec<u8>,
    /// Binary value.
    pub value: Vec<u8>,
}

/// Outcome of finalize.
///
/// A `Partial` outcome indicates that some candidates were skipped (budget,
/// corruption, missing objects). In that case, watermark ops are suppressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizeOutcome {
    /// All candidates were scanned successfully.
    /// Watermark ops are safe to write.
    Complete,
    /// Some candidates were skipped.
    /// Watermark ops are empty; do NOT advance watermarks.
    Partial {
        /// Number of OIDs that were skipped.
        skipped_count: usize,
    },
}

/// Output of finalize: separated for two-phase persistence.
///
/// Data ops are always safe to write. Watermark ops are only produced when
/// the run is `Complete`.
#[derive(Debug)]
#[must_use]
pub struct FinalizeOutput {
    /// Seen-bitmap delta + blob context + findings.
    /// Sorted by key within each namespace, namespaces in order:
    /// `bc\0` (blob_ctx) -> `fn\0` (finding) -> `sb\0` (seen_blob).
    pub data_ops: Vec<WriteOp>,
    /// Ref watermark updates. Empty if outcome is `Partial`.
    /// Sorted by key (ref_name within the `rw` namespace).
    pub watermark_ops: Vec<WriteOp>,
    /// Whether the run was complete or partial.
    pub outcome: FinalizeOutcome,
    /// Statistics for observability.
    pub stats: FinalizeStats,
}

/// Finalize statistics.
///
/// Counts are derived from the persisted data, not from raw scan input.
/// Populated only when `perf-stats` is enabled in debug builds.
#[derive(Clone, Copy, Debug, Default)]
pub struct FinalizeStats {
    /// Unique blob OIDs processed.
    pub unique_blobs: u64,
    /// Total findings persisted (after dedup).
    pub total_findings: u64,
    /// Total data ops generated.
    pub data_ops_count: u64,
    /// Total watermark ops generated.
    pub watermark_ops_count: u64,
    /// Number of duplicate findings removed.
    pub findings_deduped: u64,
}

/// Per-namespace operation counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NamespaceCounts {
    /// Blob context ops.
    pub blob_ctx: u64,
    /// Finding ops.
    pub finding: u64,
    /// Seen-bitmap scope ops.
    pub seen_blob: u64,
    /// Ref watermark ops.
    pub ref_watermark: u64,
}

/// Returns the finding slice for a span produced by the engine adapter.
///
/// The span must be in-bounds for `arena`; this is enforced by an assertion.
fn finding_slice(span: FindingSpan, arena: &[ScoredFinding]) -> &[ScoredFinding] {
    let start = span.start as usize;
    let end = start.saturating_add(span.len as usize);
    assert!(
        end <= arena.len(),
        "finding span out of bounds: start={}, len={}, arena_len={}",
        span.start,
        span.len,
        arena.len(),
    );
    &arena[start..end]
}

// =============================================================================
// Key builders (no-alloc-per-call pattern: pre-sized Vec)
// =============================================================================

/// Fixed overhead for blob-keyed namespaces:
/// 3 (ns) + 8 (repo_id) + 32 (policy_hash) + oid_len
fn blob_key_len(oid: &OidBytes) -> usize {
    3 + 8 + 32 + oid.len() as usize
}

/// Fixed overhead for finding keys:
/// 3 (ns) + 8 (repo_id) + 32 (policy_hash) + oid_len + 4 (start) + 4 (end)
/// + 4 (rule_id) + 32 (norm_hash)
fn finding_key_len(oid: &OidBytes) -> usize {
    3 + 8 + 32 + oid.len() as usize + 4 + 4 + 4 + 32
}

/// Ref watermark key length:
/// 2 (ns "rw") + 8 (repo_id) + 32 (policy_hash) + 32 (start_set_id)
/// + ref_name.len() + 1 (null)
fn ref_wm_key_len(ref_name: &[u8]) -> usize {
    2 + 8 + 32 + 32 + ref_name.len() + 1
}

/// Byte length of the fixed-width seen-bitmap scope key.
const SEEN_SCOPE_KEY_LEN: usize = 43;
/// Byte length of the fixed-width seen-bitmap staging key (same layout).
const SEEN_STAGING_KEY_LEN: usize = 43;

/// Builds a key for blob-keyed namespaces.
///
/// Big-endian numeric fields preserve lexicographic ordering across stores.
pub(crate) fn build_blob_key(
    ns: &[u8; 3],
    repo_id: u64,
    policy_hash: &[u8; 32],
    oid: &OidBytes,
) -> Vec<u8> {
    let cap = blob_key_len(oid);
    let mut key = Vec::with_capacity(cap);
    key.extend_from_slice(ns);
    key.extend_from_slice(&repo_id.to_be_bytes());
    key.extend_from_slice(policy_hash);
    key.extend_from_slice(oid.as_slice());
    debug_assert_eq!(key.len(), cap);
    key
}

/// Builds the scope key for the seen bitmap.
pub fn build_seen_scope_key(repo_id: u64, policy_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(SEEN_SCOPE_KEY_LEN);
    key.extend_from_slice(&NS_SEEN_BLOB);
    key.extend_from_slice(&repo_id.to_be_bytes());
    key.extend_from_slice(policy_hash);
    debug_assert_eq!(key.len(), SEEN_SCOPE_KEY_LEN);
    key
}

/// Builds the staging key for spill-stage seen-bitmap deltas.
///
/// Same layout as the live scope key but under the `ss\0` namespace.
/// Spill writes go here; `commit_finalize` folds into the live key.
pub fn build_seen_staging_key(repo_id: u64, policy_hash: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(SEEN_STAGING_KEY_LEN);
    key.extend_from_slice(&NS_SEEN_STAGING);
    key.extend_from_slice(&repo_id.to_be_bytes());
    key.extend_from_slice(policy_hash);
    debug_assert_eq!(key.len(), SEEN_STAGING_KEY_LEN);
    key
}

/// Builds a finding key for a specific blob OID and finding tuple.
///
/// `confidence_score` is intentionally excluded: the persistence layer tracks
/// finding identity for dedup, not scoring metadata. The score is carried
/// in the real-time `FindingEvent` stream only.
fn build_finding_key(
    repo_id: u64,
    policy_hash: &[u8; 32],
    oid: &OidBytes,
    finding: &FindingKey,
) -> Vec<u8> {
    let cap = finding_key_len(oid);
    let mut key = Vec::with_capacity(cap);
    key.extend_from_slice(&NS_FINDING);
    key.extend_from_slice(&repo_id.to_be_bytes());
    key.extend_from_slice(policy_hash);
    key.extend_from_slice(oid.as_slice());
    key.extend_from_slice(&finding.start.to_be_bytes());
    key.extend_from_slice(&finding.end.to_be_bytes());
    key.extend_from_slice(&finding.rule_id.to_be_bytes());
    key.extend_from_slice(&finding.norm_hash);
    debug_assert_eq!(key.len(), cap);
    key
}

/// Builds a ref watermark key (null-terminated ref name for prefix scans).
///
/// # Panics (debug only)
///
/// Debug-asserts that `ref_name` contains no NUL bytes. Git ref names are
/// NUL-terminated in the wire protocol and on-disk format, so embedded NULs
/// are structurally impossible from well-formed repositories. The check
/// catches programming errors during development without risking a
/// process-wide panic in production on corrupt ref data.
pub fn build_ref_wm_key(
    repo_id: u64,
    policy_hash: &[u8; 32],
    start_set_id: &StartSetId,
    ref_name: &[u8],
) -> Vec<u8> {
    // The null terminator keeps keys prefix-safe for ref name scans.
    debug_assert!(
        !ref_name.contains(&0),
        "ref_name must not contain null bytes"
    );
    let cap = ref_wm_key_len(ref_name);
    let mut key = Vec::with_capacity(cap);
    key.extend_from_slice(&NS_REF_WATERMARK);
    key.extend_from_slice(&repo_id.to_be_bytes());
    key.extend_from_slice(policy_hash);
    key.extend_from_slice(start_set_id);
    key.extend_from_slice(ref_name);
    key.push(0); // null terminator
    debug_assert_eq!(key.len(), cap);
    key
}

// =============================================================================
// Context value encoding
// =============================================================================

/// Encode canonical context into a binary value.
///
/// Format:
/// ```text
/// commit_id_be (4B) || parent_idx (1B) || change_kind (1B) ||
/// ctx_flags_be (2B) || cand_flags_be (2B) || path_len_be (4B) || path_bytes
/// ```
fn encode_ctx_value(out: &mut Vec<u8>, ctx: CandidateContext, path: &[u8]) {
    let path_len: u32 = path
        .len()
        .try_into()
        .expect("path length exceeds u32::MAX; limits should prevent this");
    let cap = 4 + 1 + 1 + 2 + 2 + 4 + path.len();
    out.clear();
    out.reserve(cap);
    out.extend_from_slice(&ctx.commit_id.to_be_bytes());
    out.push(ctx.parent_idx);
    out.push(ctx.change_kind.as_u8());
    out.extend_from_slice(&ctx.ctx_flags.to_be_bytes());
    out.extend_from_slice(&ctx.cand_flags.to_be_bytes());
    out.extend_from_slice(&path_len.to_be_bytes());
    out.extend_from_slice(path);
    debug_assert_eq!(out.len(), cap);
}

// =============================================================================
// Canonical context comparison (strict total order)
// =============================================================================

/// Compare two canonical contexts using the strict total order.
///
/// Order: commit_id, path bytes, parent_idx, change_kind, ctx_flags, cand_flags.
fn cmp_ctx(
    a_ctx: CandidateContext,
    a_path: &[u8],
    b_ctx: CandidateContext,
    b_path: &[u8],
) -> Ordering {
    a_ctx
        .commit_id
        .cmp(&b_ctx.commit_id)
        .then_with(|| a_path.cmp(b_path))
        .then_with(|| a_ctx.parent_idx.cmp(&b_ctx.parent_idx))
        .then_with(|| a_ctx.change_kind.as_u8().cmp(&b_ctx.change_kind.as_u8()))
        .then_with(|| a_ctx.ctx_flags.cmp(&b_ctx.ctx_flags))
        .then_with(|| a_ctx.cand_flags.cmp(&b_ctx.cand_flags))
}

// =============================================================================
// MARKER value
// =============================================================================

/// Marker value for finding keys.
///
/// The value is intentionally constant: presence is sufficient.
#[inline]
fn marker_value() -> Vec<u8> {
    vec![1u8]
}

// =============================================================================
// Core builder
// =============================================================================

/// Build finalize write operations from scan results.
///
/// This is a pure function: no I/O, no side effects. The returned
/// `FinalizeOutput` contains separated data and watermark ops for
/// two-phase persistence.
///
/// # Algorithm
/// 1. Sort blobs by OID and refs by name.
/// 2. For each OID group, pick the canonical context and encode it as
///    `blob_ctx`.
/// 3. Gather findings across contexts, sort + dedupe, and emit `finding` ops.
/// 4. Emit a single `seen_blob` scope delta containing all unique scanned OIDs.
/// 5. If complete, emit ref watermarks.
///
/// # Postconditions
/// - `data_ops` keys are sorted (namespace order: bc < fn < sb)
/// - `watermark_ops` keys are sorted by ref_name
/// - If `outcome == Partial`, `watermark_ops` is empty
pub fn build_finalize_ops(mut input: FinalizeInput<'_>) -> FinalizeOutput {
    // Capture skip count before any moves.
    let skipped_count = input.skipped_candidate_oids.len();
    let complete = skipped_count == 0;
    let outcome = if complete {
        FinalizeOutcome::Complete
    } else {
        FinalizeOutcome::Partial { skipped_count }
    };

    // Sort inputs for deterministic processing.
    input
        .scanned_blobs
        .sort_unstable_by(|a, b| a.oid.cmp(&b.oid));

    input
        .refs
        .sort_unstable_by(|a, b| a.ref_name.cmp(&b.ref_name));
    input.refs.dedup_by(|a, b| {
        let same = a.ref_name == b.ref_name;
        if same {
            debug_assert_eq!(
                a.tip_oid, b.tip_oid,
                "duplicate ref_name with different tip_oid"
            );
            debug_assert_eq!(
                a.tip_generation, b.tip_generation,
                "duplicate ref_name with different tip_generation"
            );
        }
        same
    });

    // Allocate separate namespace buckets (sort elimination).
    let blob_count = input.scanned_blobs.len();
    let mut ops_ctx: Vec<WriteOp> = Vec::with_capacity(blob_count);
    let mut ops_finding: Vec<WriteOp> = Vec::with_capacity(blob_count * 2);
    let mut seen_oids: Vec<OidBytes> = Vec::with_capacity(blob_count);

    // Reusable scratch buffers to avoid per-blob allocations.
    let mut ctx_val: Vec<u8> = Vec::with_capacity(128);
    let mut blob_findings: Vec<ScoredFinding> = Vec::with_capacity(64);

    let mut stats = FinalizeStats::default();

    // Group-by-OID loop (blobs are sorted, so equal OIDs are adjacent).
    let blobs = &input.scanned_blobs;
    let mut i: usize = 0;

    while i < blobs.len() {
        let oid = blobs[i].oid;
        let mut j = i + 1;
        while j < blobs.len() && blobs[j].oid == oid {
            j += 1;
        }
        // blobs[i..j] all share the same OID.

        // --- Canonical context selection (minimum under total order) ---
        let mut best_idx = i;
        let mut best_path = input.path_arena.get(blobs[i].ctx.path_ref);
        for k in (i + 1)..j {
            let path = input.path_arena.get(blobs[k].ctx.path_ref);
            if cmp_ctx(blobs[k].ctx, path, blobs[best_idx].ctx, best_path) == Ordering::Less {
                best_idx = k;
                best_path = path;
            }
        }

        // --- 1. blob_ctx (namespace "bc\0") ---
        encode_ctx_value(&mut ctx_val, blobs[best_idx].ctx, best_path);
        ops_ctx.push(WriteOp {
            key: build_blob_key(&NS_BLOB_CTX, input.repo_id, &input.policy_hash, &oid),
            value: ctx_val.clone(),
        });

        // --- 2. findings (namespace "fn\0") ---
        blob_findings.clear();
        for blob in &blobs[i..j] {
            let findings = finding_slice(blob.findings, input.finding_arena);
            blob_findings.extend_from_slice(findings);
        }
        let pre_dedup = blob_findings.len();
        sort_and_dedupe_findings(&mut blob_findings);
        perf_stats::sat_add_u64(
            &mut stats.findings_deduped,
            (pre_dedup - blob_findings.len()) as u64,
        );

        for f in &blob_findings {
            ops_finding.push(WriteOp {
                key: build_finding_key(input.repo_id, &input.policy_hash, &oid, &f.key),
                value: marker_value(),
            });
        }
        perf_stats::sat_add_u64(&mut stats.total_findings, blob_findings.len() as u64);

        // --- 3. seen_blob scope delta (namespace "sb\0") ---
        seen_oids.push(oid);

        perf_stats::sat_add_u64(&mut stats.unique_blobs, 1);
        i = j;
    }

    let mut ops_seen: Vec<WriteOp> = Vec::with_capacity(usize::from(!seen_oids.is_empty()));
    if !seen_oids.is_empty() {
        // `seen_oids` collects one OID per group from the sorted-by-OID
        // loop above, so the vector is already sorted and duplicate-free.
        let delta = SeenBitmapDelta::from_canonical_oids(seen_oids)
            .expect("scanned blobs always use a single object format");
        ops_seen.push(WriteOp {
            key: build_seen_scope_key(input.repo_id, &input.policy_hash),
            value: delta.serialize(),
        });
    }

    // Assemble data ops in namespace order: bc < fn < sb.
    let mut data_ops = ops_ctx;
    data_ops.append(&mut ops_finding);
    data_ops.append(&mut ops_seen);
    perf_stats::set_u64(&mut stats.data_ops_count, data_ops.len() as u64);

    debug_assert!(
        data_ops.windows(2).all(|w| w[0].key <= w[1].key),
        "data_ops must be sorted by key"
    );

    // Watermark ops (only if complete).
    let mut watermark_ops: Vec<WriteOp> = Vec::new();
    if complete {
        watermark_ops.reserve(input.refs.len());
        for r in &input.refs {
            let (val_buf, val_len) = encode_ref_watermark_value(&r.tip_oid, r.tip_generation);
            watermark_ops.push(WriteOp {
                key: build_ref_wm_key(
                    input.repo_id,
                    &input.policy_hash,
                    &input.start_set_id,
                    &r.ref_name,
                ),
                value: val_buf[..val_len].to_vec(),
            });
        }
    }
    perf_stats::set_u64(&mut stats.watermark_ops_count, watermark_ops.len() as u64);

    debug_assert!(
        watermark_ops.windows(2).all(|w| w[0].key <= w[1].key),
        "watermark_ops must be sorted by key"
    );

    FinalizeOutput {
        data_ops,
        watermark_ops,
        outcome,
        stats,
    }
}

// =============================================================================
// Stats helpers
// =============================================================================

impl FinalizeOutput {
    /// Compute stats breakdown by namespace for diagnostics.
    ///
    /// Counts are derived from the output ops, not the input candidates.
    pub fn compute_namespace_counts(&self) -> NamespaceCounts {
        let mut counts = NamespaceCounts::default();
        for op in &self.data_ops {
            if op.key.starts_with(&NS_BLOB_CTX) {
                counts.blob_ctx += 1;
            } else if op.key.starts_with(&NS_FINDING) {
                counts.finding += 1;
            } else if op.key.starts_with(&NS_SEEN_BLOB) {
                counts.seen_blob += 1;
            }
        }
        counts.ref_watermark = self.watermark_ops.len() as u64;
        counts
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_arena::ByteRef;
    use crate::tree_candidate::ChangeKind;

    fn test_oid(val: u8) -> OidBytes {
        OidBytes::sha1([val; 20])
    }

    fn ctx(commit_id: u32, path_ref: ByteRef) -> CandidateContext {
        CandidateContext {
            commit_id,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref,
        }
    }

    fn finding(start: u32, end: u32, rule_id: u32) -> ScoredFinding {
        ScoredFinding {
            key: FindingKey {
                start,
                end,
                rule_id,
                norm_hash: [0xAA; 32],
            },
            confidence_score: 0,
        }
    }

    fn finding_with_hash(start: u32, end: u32, rule_id: u32, hash_byte: u8) -> ScoredFinding {
        ScoredFinding {
            key: FindingKey {
                start,
                end,
                rule_id,
                norm_hash: [hash_byte; 32],
            },
            confidence_score: 0,
        }
    }

    fn push_findings(arena: &mut Vec<ScoredFinding>, findings: &[ScoredFinding]) -> FindingSpan {
        let start = arena.len();
        arena.extend_from_slice(findings);
        FindingSpan {
            start: start as u32,
            len: findings.len() as u32,
        }
    }

    fn basic_input<'a>(
        arena: &'a mut ByteArena,
        finding_arena: &'a mut Vec<ScoredFinding>,
    ) -> FinalizeInput<'a> {
        let path_ref = arena.intern(b"src/main.rs").unwrap();
        let span_a = push_findings(finding_arena, &[finding(0, 15, 1)]);
        let span_b = push_findings(finding_arena, &[]);
        FinalizeInput {
            repo_id: 42,
            policy_hash: [0xBB; 32],
            start_set_id: [0xCC; 32],
            refs: vec![RefEntry {
                ref_name: b"refs/heads/main".to_vec(),
                tip_oid: test_oid(0x01),
                tip_generation: NonZeroU32::new(1).unwrap(),
            }],
            scanned_blobs: vec![
                ScannedBlob {
                    oid: test_oid(0x10),
                    ctx: ctx(1, path_ref),
                    findings: span_a,
                },
                ScannedBlob {
                    oid: test_oid(0x20),
                    ctx: ctx(2, path_ref),
                    findings: span_b,
                },
            ],
            finding_arena: &*finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &*arena,
        }
    }

    #[test]
    fn complete_run_produces_all_ops() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let out = build_finalize_ops(basic_input(&mut arena, &mut finding_arena));

        assert_eq!(out.outcome, FinalizeOutcome::Complete);
        assert!(!out.watermark_ops.is_empty());

        let counts = out.compute_namespace_counts();
        assert_eq!(counts.blob_ctx, 2);
        assert_eq!(counts.finding, 1);
        assert_eq!(counts.seen_blob, 1);
        assert_eq!(counts.ref_watermark, 1);
    }

    #[test]
    fn partial_run_suppresses_watermarks() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let mut input = basic_input(&mut arena, &mut finding_arena);
        input.skipped_candidate_oids.push(test_oid(0xFF));

        let out = build_finalize_ops(input);

        assert_eq!(out.outcome, FinalizeOutcome::Partial { skipped_count: 1 });
        assert!(out.watermark_ops.is_empty());
    }

    #[test]
    fn data_ops_are_globally_sorted() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let out = build_finalize_ops(basic_input(&mut arena, &mut finding_arena));
        for pair in out.data_ops.windows(2) {
            assert!(pair[0].key <= pair[1].key);
        }
    }

    #[test]
    fn canonical_context_selects_minimum() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let path_ref = arena.intern(b"src/main.rs").unwrap();
        let span = push_findings(&mut finding_arena, &[]);
        let input = FinalizeInput {
            repo_id: 1,
            policy_hash: [0; 32],
            start_set_id: [0; 32],
            refs: vec![],
            scanned_blobs: vec![
                ScannedBlob {
                    oid: test_oid(0xAA),
                    ctx: ctx(10, path_ref),
                    findings: span,
                },
                ScannedBlob {
                    oid: test_oid(0xAA),
                    ctx: ctx(5, path_ref),
                    findings: span,
                },
            ],
            finding_arena: &finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &arena,
        };

        let out = build_finalize_ops(input);
        crate::test_utils::assert_perf_u64(out.stats.unique_blobs, 1);

        let ctx_op = out
            .data_ops
            .iter()
            .find(|op| op.key.starts_with(&NS_BLOB_CTX))
            .unwrap();
        let commit_id = u32::from_be_bytes(ctx_op.value[..4].try_into().unwrap());
        assert_eq!(commit_id, 5);
    }

    #[test]
    fn canonical_context_tiebreak_by_path() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let path_ref_a = arena.intern(b"z/file.rs").unwrap();
        let path_ref_b = arena.intern(b"a/file.rs").unwrap();
        let span = push_findings(&mut finding_arena, &[]);
        let input = FinalizeInput {
            repo_id: 1,
            policy_hash: [0; 32],
            start_set_id: [0; 32],
            refs: vec![],
            scanned_blobs: vec![
                ScannedBlob {
                    oid: test_oid(0xBB),
                    ctx: ctx(1, path_ref_a),
                    findings: span,
                },
                ScannedBlob {
                    oid: test_oid(0xBB),
                    ctx: ctx(1, path_ref_b),
                    findings: span,
                },
            ],
            finding_arena: &finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &arena,
        };

        let out = build_finalize_ops(input);
        let ctx_op = out
            .data_ops
            .iter()
            .find(|op| op.key.starts_with(&NS_BLOB_CTX))
            .unwrap();

        let path_len = u32::from_be_bytes(ctx_op.value[10..14].try_into().unwrap()) as usize;
        let path = &ctx_op.value[14..14 + path_len];
        assert_eq!(path, b"a/file.rs");
    }

    #[test]
    fn findings_deduped_across_paths() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let path_ref_a = arena.intern(b"a/file.rs").unwrap();
        let path_ref_b = arena.intern(b"b/file.rs").unwrap();
        let f = finding(0, 15, 1);
        let span_a = push_findings(&mut finding_arena, &[f]);
        let span_b = push_findings(&mut finding_arena, &[f]);
        let input = FinalizeInput {
            repo_id: 1,
            policy_hash: [0; 32],
            start_set_id: [0; 32],
            refs: vec![],
            scanned_blobs: vec![
                ScannedBlob {
                    oid: test_oid(0xCC),
                    ctx: ctx(1, path_ref_a),
                    findings: span_a,
                },
                ScannedBlob {
                    oid: test_oid(0xCC),
                    ctx: ctx(2, path_ref_b),
                    findings: span_b,
                },
            ],
            finding_arena: &finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &arena,
        };

        let out = build_finalize_ops(input);
        crate::test_utils::assert_perf_u64(out.stats.total_findings, 1);
        crate::test_utils::assert_perf_u64(out.stats.findings_deduped, 1);
    }

    #[test]
    fn findings_deduped_when_only_confidence_differs() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let path_ref = arena.intern(b"a/file.rs").unwrap();
        let mut low = finding(0, 15, 1);
        low.confidence_score = 1;
        let mut high = finding(0, 15, 1);
        high.confidence_score = 6;
        let span = push_findings(&mut finding_arena, &[low, high]);

        // Verify that sort_and_dedupe keeps the highest confidence winner.
        let mut dedup_check = finding_arena.clone();
        sort_and_dedupe_findings(&mut dedup_check);
        assert_eq!(dedup_check.len(), 1, "identity-equal findings must dedup");
        assert_eq!(
            dedup_check[0].confidence_score, 6,
            "highest confidence must survive dedup"
        );

        let input = FinalizeInput {
            repo_id: 1,
            policy_hash: [0; 32],
            start_set_id: [0; 32],
            refs: vec![],
            scanned_blobs: vec![ScannedBlob {
                oid: test_oid(0xCE),
                ctx: ctx(1, path_ref),
                findings: span,
            }],
            finding_arena: &finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &arena,
        };

        let out = build_finalize_ops(input);
        crate::test_utils::assert_perf_u64(out.stats.total_findings, 1);
        crate::test_utils::assert_perf_u64(out.stats.findings_deduped, 1);
    }

    #[test]
    fn distinct_findings_preserved() {
        let mut arena = ByteArena::with_capacity(1024);
        let mut finding_arena = Vec::new();
        let path_ref = arena.intern(b"a/file.rs").unwrap();
        let span = push_findings(
            &mut finding_arena,
            &[
                finding(0, 15, 1),
                finding(20, 30, 2),
                finding_with_hash(0, 15, 1, 0xBB),
            ],
        );
        let input = FinalizeInput {
            repo_id: 1,
            policy_hash: [0; 32],
            start_set_id: [0; 32],
            refs: vec![],
            scanned_blobs: vec![ScannedBlob {
                oid: test_oid(0xDD),
                ctx: ctx(1, path_ref),
                findings: span,
            }],
            finding_arena: &finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &arena,
        };

        let out = build_finalize_ops(input);
        crate::test_utils::assert_perf_u64(out.stats.total_findings, 3);
        crate::test_utils::assert_perf_u64(out.stats.findings_deduped, 0);
    }

    #[test]
    fn watermark_ops_sorted_by_ref_name() {
        let arena = ByteArena::with_capacity(1024);
        let finding_arena = Vec::new();
        let input = FinalizeInput {
            repo_id: 1,
            policy_hash: [0; 32],
            start_set_id: [0; 32],
            refs: vec![
                RefEntry {
                    ref_name: b"refs/heads/z-branch".to_vec(),
                    tip_oid: test_oid(0x01),
                    tip_generation: NonZeroU32::new(10).unwrap(),
                },
                RefEntry {
                    ref_name: b"refs/heads/a-branch".to_vec(),
                    tip_oid: test_oid(0x02),
                    tip_generation: NonZeroU32::new(20).unwrap(),
                },
                RefEntry {
                    ref_name: b"refs/heads/main".to_vec(),
                    tip_oid: test_oid(0x03),
                    tip_generation: NonZeroU32::new(30).unwrap(),
                },
            ],
            scanned_blobs: vec![],
            finding_arena: &finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &arena,
        };

        let out = build_finalize_ops(input);
        assert_eq!(out.watermark_ops.len(), 3);
        for pair in out.watermark_ops.windows(2) {
            assert!(pair[0].key < pair[1].key);
        }
    }

    #[test]
    fn watermark_value_encodes_oid() {
        let arena = ByteArena::with_capacity(1024);
        let finding_arena = Vec::new();
        let tip = test_oid(0xAB);
        let input = FinalizeInput {
            repo_id: 1,
            policy_hash: [0; 32],
            start_set_id: [0; 32],
            refs: vec![RefEntry {
                ref_name: b"refs/heads/main".to_vec(),
                tip_oid: tip,
                tip_generation: NonZeroU32::new(41).unwrap(),
            }],
            scanned_blobs: vec![],
            finding_arena: &finding_arena,
            skipped_candidate_oids: vec![],
            path_arena: &arena,
        };

        let out = build_finalize_ops(input);
        let wm = &out.watermark_ops[0];
        assert_eq!(wm.value[0], 20);
        assert_eq!(&wm.value[1..21], tip.as_slice());
        assert_eq!(&wm.value[21..25], &41u32.to_le_bytes());
    }
}
