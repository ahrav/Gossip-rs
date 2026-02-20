//! Split operation types and payload hash functions.
//!
//! Contains the plan/result types for SplitReplace and SplitResidual
//! operations, the deterministic shard ID derivation function, and the
//! payload hash functions used for op-log conflict detection.
//!
//! ## Design Decisions (locked)
//!
//! D2.9: Split operations carry structured ShardSpecs. The coordinator
//!       validates range coverage via `validate_split_coverage` /
//!       `validate_residual_split` from `shard_spec` before executing.
//!
//! D2.10: `derive_split_shard_id` uses `CanonicalBytes` internally and
//!        sets bit 63 to distinguish derived IDs from root IDs. Pure
//!        function: same inputs → same output. Idempotent splits.
//!
//!        Reference: Content-addressed identity pattern (Git, IPFS);
//!        §3.1 exactly-once semantics via deterministic IDs.

use blake3::Hasher;

use crate::identity::{
    CanonicalBytes, OpId, RunId, ShardId,
    domain, domain_hasher, finalize_64,
};
use crate::coordination::cursor::Cursor;
use crate::coordination::shard_spec::ShardSpec;
use crate::coordination::record::ParkReason;

// ============================================================================
// § Split Plan / Result Types
// ============================================================================

/// A single child in a SplitReplace plan.
///
/// Each child has a structured ShardSpec (with key range) and an initial
/// cursor. Typically the cursor is initial (no progress), but a worker
/// that has partially processed a sub-range may set a non-initial cursor
/// for the child covering that sub-range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplaceChild {
    pub spec: ShardSpec,
    pub cursor: Cursor,
}

impl CanonicalBytes for SplitReplaceChild {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.spec.write_canonical(h);
        self.cursor.write_canonical(h);
    }
}

/// Plan for replacing a shard with N children.
///
/// The coordinator validates that the children's key ranges collectively
/// cover the parent's range exactly (no gaps, no overlaps) using
/// `validate_split_coverage` from `shard_spec`.
///
/// After validation, the coordinator:
/// 1. Derives deterministic ShardIds for each child via `derive_split_shard_id`.
/// 2. Creates child ShardRecords (status: Active).
/// 3. Sets the parent's status to Split.
/// 4. Records the child IDs in the parent's `spawned` list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplacePlan {
    pub children: Vec<SplitReplaceChild>,
}

impl CanonicalBytes for SplitReplacePlan {
    fn write_canonical(&self, h: &mut Hasher) {
        (self.children.len() as u32).write_canonical(h);
        for child in &self.children {
            child.write_canonical(h);
        }
    }
}

/// Result of a SplitReplace operation — the derived child shard IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplaceResult {
    pub children: Vec<ShardId>,
}

/// Plan for shrinking a shard and creating a residual.
///
/// A residual split is for when a worker realizes its assigned range is
/// too large and wants to hand off the unprocessed portion:
///
/// ```text
/// old_parent:  [─────────────────────────)
/// new_parent:  [──────────)
/// residual:               [─────────────)
/// ```
///
/// The parent keeps the left portion (lower keys, already partially
/// processed). The residual gets the right portion (higher keys,
/// unprocessed). This aligns with cursor monotonicity: the parent's
/// cursor has been advancing through the lower keys.
///
/// The coordinator validates coverage via `validate_residual_split`
/// from `shard_spec`.
///
/// After validation:
/// 1. Derives a deterministic ShardId for the residual.
/// 2. Updates the parent's spec to `parent_new_spec`.
/// 3. Creates the residual ShardRecord (status: Active).
/// 4. Records the residual ID in the parent's `spawned` list.
/// 5. Parent remains Active (it continues processing its shrunk range).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResidualPlan {
    pub parent_new_spec: ShardSpec,
    pub residual_spec: ShardSpec,
}

impl CanonicalBytes for SplitResidualPlan {
    fn write_canonical(&self, h: &mut Hasher) {
        self.parent_new_spec.write_canonical(h);
        self.residual_spec.write_canonical(h);
    }
}

/// Result of a SplitResidual operation — the derived residual shard ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitResidualResult {
    pub residual: ShardId,
}

// ============================================================================
// § DerivedShardKind
// ============================================================================

/// Discriminant for the kind of shard being derived from a split.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DerivedShardKind {
    /// A child shard in a SplitReplace operation.
    Child = 0,
    /// The residual shard in a SplitResidual operation.
    Residual = 1,
}

impl CanonicalBytes for DerivedShardKind {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        (*self as u8).write_canonical(h);
    }
}

// ============================================================================
// § derive_split_shard_id
// ============================================================================

/// Derive a deterministic `ShardId` for a split operation.
///
/// Makes split operations idempotent under retries: the same inputs
/// always produce the same shard ID, so retrying a split doesn't
/// create duplicate shards.
///
/// ## Derivation
///
/// ```text
/// raw = blake3("gossip/coord/v1/split-id",
///     run_id || parent_shard_id || op_id || kind || index)
/// shard_id = truncate_64(raw) | (1 << 63)
/// ```
///
/// The top bit is set to distinguish derived IDs from root shard IDs
/// (which are small sequential integers 0..N). This is a deterministic
/// convention, not a cryptographic guarantee — it prevents collisions
/// with the most common root ID patterns.
///
/// ## Invariants
///
/// **Safety (determinism)**: Pure function of inputs. Same inputs →
/// same ShardId, always.
///
/// **Safety (uniqueness)**: Different (run, parent, op, kind, index)
/// tuples produce different ShardIds (with ~64-bit collision resistance,
/// reduced to ~63 bits by the top-bit convention).
///
/// Reference: Content-addressed identity pattern (Git, IPFS);
///            §3.1 exactly-once semantics via deterministic IDs.
pub fn derive_split_shard_id(
    run: RunId,
    parent: ShardId,
    op: OpId,
    kind: DerivedShardKind,
    index: u32,
) -> ShardId {
    let mut h = domain_hasher(domain::SPLIT_ID_V1);
    run.write_canonical(&mut h);
    parent.write_canonical(&mut h);
    op.write_canonical(&mut h);
    kind.write_canonical(&mut h);
    index.write_canonical(&mut h);

    let out = h.finalize();
    let bytes: [u8; 8] = out.as_bytes()[0..8]
        .try_into()
        .expect("8 bytes from 32");
    let mut id = u64::from_le_bytes(bytes);

    // Reserve the top half of the ID space for derived shards.
    id |= 1u64 << 63;

    ShardId(id)
}

// ============================================================================
// § Payload Hash Functions
// ============================================================================

/// Compute a 64-bit payload hash for an operation.
///
/// Used for op-log conflict detection: same OpId with different payload
/// hash = accidental reuse, rejected. Same OpId with same payload hash
/// = legitimate retry, cached result returned.
///
/// Not cryptographic. 64 bits of collision resistance is sufficient for
/// this guardrail purpose (birthday bound ≈ 2^32 operations before
/// expected collision, far beyond any single shard's lifetime).
///
/// The `op_tag` provides domain separation between operation types
/// within the `OP_PAYLOAD_V1` namespace.
pub(crate) fn op_payload_hash(op_tag: &[u8], write_fields: impl FnOnce(&mut Hasher)) -> u64 {
    let mut h = domain_hasher(domain::OP_PAYLOAD_V1);
    op_tag.write_canonical(&mut h);
    write_fields(&mut h);
    finalize_64(&h)
}

/// Payload hash for a Checkpoint operation.
pub fn hash_checkpoint_payload(new_cursor: &Cursor) -> u64 {
    op_payload_hash(b"checkpoint", |h| {
        new_cursor.write_canonical(h);
    })
}

/// Payload hash for a Complete operation.
pub fn hash_complete_payload(final_cursor: &Cursor) -> u64 {
    op_payload_hash(b"complete", |h| {
        final_cursor.write_canonical(h);
    })
}

/// Payload hash for a Park operation.
pub fn hash_park_payload(reason: ParkReason) -> u64 {
    op_payload_hash(b"park", |h| {
        reason.write_canonical(h);
    })
}

/// Payload hash for a SplitReplace operation.
pub fn hash_split_replace_payload(plan: &SplitReplacePlan) -> u64 {
    op_payload_hash(b"split_replace", |h| {
        plan.write_canonical(h);
    })
}

/// Payload hash for a SplitResidual operation.
pub fn hash_split_residual_payload(plan: &SplitResidualPlan) -> u64 {
    op_payload_hash(b"split_residual", |h| {
        plan.write_canonical(h);
    })
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    // -- derive_split_shard_id --

    // TODO: test derive_split_shard_id_deterministic
    //   - Same inputs → same output

    // TODO: test derive_split_shard_id_top_bit_set
    //   - id.0 & (1 << 63) != 0

    // TODO: test derive_split_shard_id_different_index_different_id
    // TODO: test derive_split_shard_id_different_kind_different_id
    //   - Child vs Residual with same other inputs → different IDs

    // TODO: test derive_split_shard_id_different_parent_different_id
    // TODO: test derive_split_shard_id_different_op_different_id

    // -- Payload hash functions --

    // TODO: test hash_checkpoint_deterministic
    // TODO: test hash_checkpoint_sensitive_to_cursor

    // TODO: test hash_complete_deterministic

    // TODO: test hash_checkpoint_vs_complete_different
    //   - Same cursor, different operation tag → different hash

    // TODO: test hash_park_deterministic
    // TODO: test hash_park_sensitive_to_reason

    // TODO: test hash_split_replace_deterministic
    // TODO: test hash_split_replace_sensitive_to_children

    // TODO: test hash_split_residual_deterministic

    // -- SplitReplacePlan CanonicalBytes --

    // TODO: test split_replace_plan_canonical_deterministic
    // TODO: test split_replace_plan_different_children_different_hash

    // -- Property-based (proptest) --

    // TODO: proptest derive_split_shard_id_is_pure
    //   - ∀ inputs: two calls → same output, top bit set

    // TODO: proptest hash_checkpoint_is_pure
    // TODO: proptest hash_park_is_pure
}
