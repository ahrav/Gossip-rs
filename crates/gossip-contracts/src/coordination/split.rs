//! Split operation types and shard-ID/payload-hash derivation functions.
//!
//! When a shard's key range becomes too large or unevenly distributed,
//! the coordinator splits it into smaller shards. Two strategies exist:
//!
//! - **Split-replace** ([`SplitReplacePlan`]): the parent is retired and
//!   replaced by ≥ 2 children that collectively cover its entire key range.
//!   Use when the parent's range should be evenly subdivided.
//!
//! - **Split-residual** ([`SplitResidualPlan`]): the parent shrinks its
//!   key range and a new *residual* shard covers the remainder. Use when
//!   the parent should keep scanning a prefix while offloading the tail.
//!
//! Both strategies produce deterministic child shard IDs via
//! [`derive_split_shard_id`], and all operations are fingerprinted for
//! op-log idempotency via the `hash_*_payload` functions.
//!
//! ## Design Decisions (locked)
//!
//! D2.8: Derived shard IDs have bit 63 set — distinguishing root shards
//!       (externally assigned) from split-derived shards (deterministically
//!       computed). Birthday collision bound ~2^32 values before 50%
//!       collision probability; acceptable for bounded coordination use
//!       cases.
//!
//! D2.9: Payload hashes use domain-separated BLAKE3 with `CanonicalBytes`
//!       encoding. This ties the op-log idempotency check to the actual
//!       operation parameters, detecting "same OpId, different payload"
//!       conflicts.

use blake3::Hasher;

use crate::coordination::cursor::Cursor;
use crate::coordination::record::ParkReason;
use crate::coordination::shard_spec::ShardSpec;
use crate::identity::hashing::{OP_PAYLOAD_HASHER, SPLIT_ID_HASHER};
use crate::identity::{CanonicalBytes, OpId, RunId, ShardId, finalize_64};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of children in a single SplitReplace operation.
///
/// Bounds the fan-out of any single split to prevent a single coordinator
/// operation from creating an unbounded number of shards. 256 children
/// allows fine-grained subdivision while keeping the per-operation metadata
/// size tractable (SEC-4: resource exhaustion guard).
pub const MAX_SPLIT_CHILDREN: usize = 256;

/// Maximum total spawned shards per parent shard.
///
/// Caps the cumulative number of children + residuals a parent may produce
/// across its lifetime (multiple split-residual operations accumulate).
/// 1024 bounds the total spawn count per parent shard (SEC-4).
pub const MAX_SPAWNED_PER_SHARD: usize = 1024;

// Relationship assertion: a single split can't exceed total spawned cap.
const _: () = assert!(MAX_SPLIT_CHILDREN <= MAX_SPAWNED_PER_SHARD);

// ============================================================================
// DerivedShardKind
// ============================================================================

/// Distinguishes child shards from residual shards in ID derivation.
///
/// Both come from a split, but play different roles: children replace the
/// parent's range, while a residual covers the unprocessed remainder.
///
/// ## Invariants
///
/// **Safety (discriminant stability)**: The `u8` discriminant values
/// participate in shard-ID derivation. Changing them would produce
/// different IDs for the same logical operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DerivedShardKind {
    Child = 0,
    Residual = 1,
}

impl DerivedShardKind {
    /// Parse a `u8` discriminant to the corresponding variant.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Child),
            1 => Some(Self::Residual),
            _ => None,
        }
    }

    /// Return the stable `u8` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for DerivedShardKind {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_u8().write_canonical(h);
    }
}

// Compile-time assertions for DerivedShardKind.
const _: () = assert!(DerivedShardKind::Child as u8 == 0);
const _: () = assert!(DerivedShardKind::Residual as u8 == 1);
const _: () = assert!(core::mem::size_of::<DerivedShardKind>() == 1);

// ============================================================================
// SplitReplaceChild
// ============================================================================

/// A single child in a [`SplitReplacePlan`].
///
/// Each child carries its own [`ShardSpec`] (the key sub-range it covers)
/// and an initial [`Cursor`] (where scanning should begin). The cursor
/// allows the coordinator to pre-position a child at the parent's last
/// checkpoint within that sub-range, avoiding re-scanning already-processed
/// keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplaceChild {
    spec: ShardSpec,
    cursor: Cursor,
}

impl SplitReplaceChild {
    /// Construct a new child entry.
    #[must_use]
    pub fn new(spec: ShardSpec, cursor: Cursor) -> Self {
        Self { spec, cursor }
    }

    /// The child's shard specification (key sub-range).
    #[inline]
    #[must_use]
    pub fn spec(&self) -> &ShardSpec {
        &self.spec
    }

    /// The child's initial cursor position.
    #[inline]
    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        &self.cursor
    }
}

impl CanonicalBytes for SplitReplaceChild {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.spec.write_canonical(h);
        self.cursor.write_canonical(h);
    }
}

// ============================================================================
// SplitReplacePlan
// ============================================================================

/// Plan for a split-replace operation: parent is replaced by ≥ 2 children
/// that collectively cover the parent's key range.
///
/// The `children` field is private — the constructor validates the
/// minimum-count invariant (≥ 2, ≤ [`MAX_SPLIT_CHILDREN`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplacePlan {
    children: Vec<SplitReplaceChild>,
}

/// Error returned when a [`SplitReplacePlan`] is constructed with an
/// invalid number of children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitReplacePlanError {
    /// Fewer than 2 children — not a split.
    TooFewChildren { count: usize },
    /// More than [`MAX_SPLIT_CHILDREN`] children.
    TooManyChildren { count: usize },
}

impl fmt::Display for SplitReplacePlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewChildren { count } => {
                write!(f, "split-replace requires >= 2 children, got {count}")
            }
            Self::TooManyChildren { count } => {
                write!(
                    f,
                    "split-replace exceeds max children ({count} > {MAX_SPLIT_CHILDREN})"
                )
            }
        }
    }
}

impl std::error::Error for SplitReplacePlanError {}

use std::fmt;

impl SplitReplacePlan {
    /// Construct a validated split-replace plan.
    ///
    /// # Errors
    ///
    /// Returns [`SplitReplacePlanError`] if `children.len() < 2` or
    /// `children.len() > MAX_SPLIT_CHILDREN`.
    pub fn try_new(children: Vec<SplitReplaceChild>) -> Result<Self, SplitReplacePlanError> {
        if children.len() < 2 {
            return Err(SplitReplacePlanError::TooFewChildren {
                count: children.len(),
            });
        }
        if children.len() > MAX_SPLIT_CHILDREN {
            return Err(SplitReplacePlanError::TooManyChildren {
                count: children.len(),
            });
        }
        Ok(Self { children })
    }

    /// The children in this plan.
    #[inline]
    #[must_use]
    pub fn children(&self) -> &[SplitReplaceChild] {
        &self.children
    }
}

impl CanonicalBytes for SplitReplacePlan {
    /// Length-prefixed encoding: `len || child[0] || child[1] || ...`.
    ///
    /// The length prefix ensures plans with different child counts produce
    /// distinct byte sequences even if the concatenated child bytes happen
    /// to collide.
    fn write_canonical(&self, h: &mut Hasher) {
        (self.children.len() as u32).write_canonical(h);
        for child in &self.children {
            child.write_canonical(h);
        }
    }
}

// ============================================================================
// SplitResidualPlan
// ============================================================================

/// Plan for a split-residual operation: parent shrinks its key range and
/// a new residual shard covers the remainder.
///
/// The parent keeps `parent_new_spec` (typically the prefix it has already
/// partially scanned) and continues processing. The residual shard gets
/// `residual_spec` (the unprocessed suffix) and starts from
/// [`Cursor::initial()`] (enforced by the coordinator, not by this type).
///
/// ## Coverage contract
///
/// `parent_new_spec ∪ residual_spec` must equal the parent's original
/// `ShardSpec` range, with no overlap. This is enforced by the coordinator
/// at execution time, not by this plan type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResidualPlan {
    parent_new_spec: ShardSpec,
    residual_spec: ShardSpec,
}

impl SplitResidualPlan {
    /// Construct a new residual plan.
    #[must_use]
    pub fn new(parent_new_spec: ShardSpec, residual_spec: ShardSpec) -> Self {
        Self {
            parent_new_spec,
            residual_spec,
        }
    }

    /// The parent's new (shrunk) specification — the range it keeps.
    #[inline]
    #[must_use]
    pub fn parent_new_spec(&self) -> &ShardSpec {
        &self.parent_new_spec
    }

    /// The residual shard's specification — the range split off.
    #[inline]
    #[must_use]
    pub fn residual_spec(&self) -> &ShardSpec {
        &self.residual_spec
    }
}

impl CanonicalBytes for SplitResidualPlan {
    fn write_canonical(&self, h: &mut Hasher) {
        self.parent_new_spec.write_canonical(h);
        self.residual_spec.write_canonical(h);
    }
}

// ============================================================================
// derive_split_shard_id
// ============================================================================

/// Deterministically derive a child/residual shard ID from the split context.
///
/// Uses domain-separated BLAKE3 (`SPLIT_ID_V1`) with five inputs:
/// `(run, parent, op, kind, index)`. The output has bit 63 set to mark
/// it as a derived ID — distinguishing it from externally-assigned root
/// shard IDs.
///
/// ## Collision Bound
///
/// BLAKE3 truncated to 64 bits gives a birthday collision probability of
/// ~50% at ~2^32 derived IDs. This is acceptable for coordination use
/// cases where the total number of derived shards per run is bounded by
/// [`MAX_SPAWNED_PER_SHARD`] × shard count.
///
/// ## Caller Responsibility
///
/// The `index` parameter must be `parent.spawned.len() as u32` at call
/// time — callers must not hardcode 0. Different indices produce different
/// IDs (tested by `derive_split_shard_id_collision_free`).
#[must_use]
pub fn derive_split_shard_id(
    run: RunId,
    parent: ShardId,
    op: OpId,
    kind: DerivedShardKind,
    index: u32,
) -> ShardId {
    let mut h = SPLIT_ID_HASHER.clone();
    run.write_canonical(&mut h);
    parent.write_canonical(&mut h);
    op.write_canonical(&mut h);
    kind.write_canonical(&mut h);
    index.write_canonical(&mut h);

    let id = finalize_64(&h) | (1u64 << 63);
    let result = ShardId::from_raw(id);
    debug_assert!(result.is_derived());
    result
}

// ============================================================================
// Payload hash functions
// ============================================================================

/// Internal helper: compute a domain-tagged payload hash.
///
/// Uses the cached `OP_PAYLOAD_HASHER` (`OP_PAYLOAD_V1` domain) and
/// prepends the operation-specific `op_tag` before calling `write_fields`.
/// The tag acts as a second domain-separation layer — even if two different
/// operation types happen to produce identical field bytes, the different
/// tags guarantee distinct hashes (tested by `hash_checkpoint_vs_complete_different`).
#[must_use]
pub(crate) fn op_payload_hash(op_tag: &[u8], write_fields: impl FnOnce(&mut Hasher)) -> u64 {
    let mut h = OP_PAYLOAD_HASHER.clone();
    h.update(op_tag);
    write_fields(&mut h);
    finalize_64(&h)
}

/// Payload hash for a checkpoint operation.
///
/// Stored in the op-log alongside the [`OpId`] to detect "same OpId,
/// different cursor" conflicts during idempotent replay.
#[must_use]
pub fn hash_checkpoint_payload(new_cursor: &Cursor) -> u64 {
    op_payload_hash(b"checkpoint", |h| {
        new_cursor.write_canonical(h);
    })
}

/// Payload hash for a complete operation.
///
/// Same role as [`hash_checkpoint_payload`] but for the terminal
/// completion event. The `b"complete"` tag ensures a completion and
/// a checkpoint with the same cursor produce different hashes.
#[must_use]
pub fn hash_complete_payload(final_cursor: &Cursor) -> u64 {
    op_payload_hash(b"complete", |h| {
        final_cursor.write_canonical(h);
    })
}

/// Payload hash for a park operation.
///
/// Fingerprints the [`ParkReason`] so the op-log can distinguish
/// "park with reason A" from "park with reason B" under the same [`OpId`].
#[must_use]
pub fn hash_park_payload(reason: ParkReason) -> u64 {
    op_payload_hash(b"park", |h| {
        reason.write_canonical(h);
    })
}

/// Payload hash for a split-replace operation.
///
/// Fingerprints the full [`SplitReplacePlan`] (child count + all child
/// specs and cursors) for op-log idempotency.
#[must_use]
pub fn hash_split_replace_payload(plan: &SplitReplacePlan) -> u64 {
    op_payload_hash(b"split_replace", |h| {
        plan.write_canonical(h);
    })
}

/// Payload hash for a split-residual operation.
///
/// Fingerprints both the parent's new spec and the residual spec for
/// op-log idempotency.
#[must_use]
pub fn hash_split_residual_payload(plan: &SplitResidualPlan) -> u64 {
    op_payload_hash(b"split_residual", |h| {
        plan.write_canonical(h);
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::canonical_digest;
    use proptest::prelude::*;

    // -- DerivedShardKind ------------------------------------------------

    #[test]
    fn derived_shard_kind_roundtrip() {
        assert_eq!(DerivedShardKind::from_u8(0), Some(DerivedShardKind::Child));
        assert_eq!(
            DerivedShardKind::from_u8(1),
            Some(DerivedShardKind::Residual)
        );
        assert_eq!(DerivedShardKind::from_u8(2), None);
        assert_eq!(DerivedShardKind::from_u8(u8::MAX), None);
    }

    #[test]
    fn derived_shard_kind_canonical_all_distinct() {
        assert_ne!(
            canonical_digest(&DerivedShardKind::Child),
            canonical_digest(&DerivedShardKind::Residual),
        );
    }

    // -- SplitReplacePlan validation -------------------------------------

    #[test]
    fn split_replace_plan_too_few_children() {
        let child = SplitReplaceChild::new(ShardSpec::unbounded(), Cursor::initial());
        let err = SplitReplacePlan::try_new(vec![child]).unwrap_err();
        assert!(matches!(
            err,
            SplitReplacePlanError::TooFewChildren { count: 1 }
        ));
    }

    #[test]
    fn split_replace_plan_valid() {
        let c1 = SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        );
        let c2 = SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        );
        assert!(SplitReplacePlan::try_new(vec![c1, c2]).is_ok());
    }

    // -- CanonicalBytes --------------------------------------------------

    #[test]
    fn split_replace_plan_canonical_deterministic() {
        let c1 = SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        );
        let c2 = SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        );
        let plan = SplitReplacePlan::try_new(vec![c1.clone(), c2.clone()]).unwrap();
        assert_eq!(canonical_digest(&plan), canonical_digest(&plan));
    }

    // -- Hash function tests ---------------------------------------------

    #[test]
    fn hash_checkpoint_vs_complete_different() {
        let cursor = Cursor::with_last_key(b"same-key".to_vec());
        assert_ne!(
            hash_checkpoint_payload(&cursor),
            hash_complete_payload(&cursor),
        );
    }

    // -- Property tests --------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        // Collision-freedom: distinct inputs → different derived shard IDs.
        #[test]
        fn derive_split_shard_id_collision_free(
            run_a in any::<u64>(), parent_a in any::<u64>(), op_a in any::<u64>(),
            kind_a in 0u8..2, index_a in any::<u32>(),
            run_b in any::<u64>(), parent_b in any::<u64>(), op_b in any::<u64>(),
            kind_b in 0u8..2, index_b in any::<u32>(),
        ) {
            let tuple_a = (run_a, parent_a, op_a, kind_a, index_a);
            let tuple_b = (run_b, parent_b, op_b, kind_b, index_b);
            prop_assume!(tuple_a != tuple_b);

            let id_a = derive_split_shard_id(
                RunId::from_raw(run_a), ShardId::from_raw(parent_a), OpId::from_raw(op_a),
                DerivedShardKind::from_u8(kind_a).unwrap(), index_a,
            );
            let id_b = derive_split_shard_id(
                RunId::from_raw(run_b), ShardId::from_raw(parent_b), OpId::from_raw(op_b),
                DerivedShardKind::from_u8(kind_b).unwrap(), index_b,
            );
            prop_assert_ne!(id_a, id_b);
        }

        // All derived IDs have bit 63 set.
        #[test]
        fn derive_split_shard_id_always_derived(
            run in any::<u64>(), parent in any::<u64>(), op in any::<u64>(),
            kind in 0u8..2, index in any::<u32>(),
        ) {
            let id = derive_split_shard_id(
                RunId::from_raw(run), ShardId::from_raw(parent), OpId::from_raw(op),
                DerivedShardKind::from_u8(kind).unwrap(), index,
            );
            prop_assert!(id.is_derived());
        }

        // Purity: same inputs → same output (subsumes deterministic unit tests).
        #[test]
        fn derive_split_shard_id_is_pure(
            run in any::<u64>(), parent in any::<u64>(), op in any::<u64>(),
            kind in 0u8..2, index in any::<u32>(),
        ) {
            let k = DerivedShardKind::from_u8(kind).unwrap();
            let a = derive_split_shard_id(RunId::from_raw(run), ShardId::from_raw(parent), OpId::from_raw(op), k, index);
            let b = derive_split_shard_id(RunId::from_raw(run), ShardId::from_raw(parent), OpId::from_raw(op), k, index);
            prop_assert_eq!(a, b);
        }

        // Checkpoint hash: collision-free.
        #[test]
        fn hash_checkpoint_collision_free(
            k1 in proptest::collection::vec(any::<u8>(), 1..64),
            k2 in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(k1 != k2);
            let c1 = Cursor::with_last_key(k1);
            let c2 = Cursor::with_last_key(k2);
            prop_assert_ne!(hash_checkpoint_payload(&c1), hash_checkpoint_payload(&c2));
        }

        // Complete hash: collision-free.
        #[test]
        fn hash_complete_collision_free(
            k1 in proptest::collection::vec(any::<u8>(), 1..64),
            k2 in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(k1 != k2);
            let c1 = Cursor::with_last_key(k1);
            let c2 = Cursor::with_last_key(k2);
            prop_assert_ne!(hash_complete_payload(&c1), hash_complete_payload(&c2));
        }

        // Park hash: collision-free.
        #[test]
        fn hash_park_collision_free(a in 0u8..5, b in 0u8..5) {
            prop_assume!(a != b);
            let ra = ParkReason::from_u8(a).unwrap();
            let rb = ParkReason::from_u8(b).unwrap();
            prop_assert_ne!(hash_park_payload(ra), hash_park_payload(rb));
        }

        // Purity: checkpoint.
        #[test]
        fn hash_checkpoint_is_pure(
            k in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let c = Cursor::with_last_key(k);
            prop_assert_eq!(hash_checkpoint_payload(&c), hash_checkpoint_payload(&c));
        }

        // Purity: complete.
        #[test]
        fn hash_complete_is_pure(
            k in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let c = Cursor::with_last_key(k);
            prop_assert_eq!(hash_complete_payload(&c), hash_complete_payload(&c));
        }

        // Purity: park.
        #[test]
        fn hash_park_is_pure(v in 0u8..5) {
            let r = ParkReason::from_u8(v).unwrap();
            prop_assert_eq!(hash_park_payload(r), hash_park_payload(r));
        }

        // Split-replace collision-free.
        #[test]
        fn hash_split_replace_collision_free(
            s1 in proptest::collection::vec(any::<u8>(), 1..16),
            s1_suffix in proptest::collection::vec(any::<u8>(), 1..8),
            s2 in proptest::collection::vec(any::<u8>(), 1..16),
            s2_suffix in proptest::collection::vec(any::<u8>(), 1..8),
        ) {
            let mut e1 = s1.clone();
            e1.extend_from_slice(&s1_suffix);
            let mut e2 = s2.clone();
            e2.extend_from_slice(&s2_suffix);

            prop_assume!((s1.clone(), e1.clone()) != (s2.clone(), e2.clone()));

            let plan1 = SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(ShardSpec::with_range(s1.clone(), e1.clone()), Cursor::initial()),
                SplitReplaceChild::new(ShardSpec::with_range(e1, vec![0xFF; 32]), Cursor::initial()),
            ]).unwrap();
            let plan2 = SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(ShardSpec::with_range(s2.clone(), e2.clone()), Cursor::initial()),
                SplitReplaceChild::new(ShardSpec::with_range(e2, vec![0xFF; 32]), Cursor::initial()),
            ]).unwrap();
            prop_assume!(plan1 != plan2);
            prop_assert_ne!(hash_split_replace_payload(&plan1), hash_split_replace_payload(&plan2));
        }

        // Split-residual collision-free.
        #[test]
        fn hash_split_residual_collision_free(
            s1 in proptest::collection::vec(any::<u8>(), 1..16),
            s1_suffix in proptest::collection::vec(any::<u8>(), 1..8),
            s2 in proptest::collection::vec(any::<u8>(), 1..16),
            s2_suffix in proptest::collection::vec(any::<u8>(), 1..8),
        ) {
            let mut e1 = s1.clone();
            e1.extend_from_slice(&s1_suffix);
            let mut e2 = s2.clone();
            e2.extend_from_slice(&s2_suffix);

            let plan1 = SplitResidualPlan::new(
                ShardSpec::with_range(s1.clone(), e1.clone()),
                ShardSpec::with_range(e1, vec![0xFF; 32]),
            );
            let plan2 = SplitResidualPlan::new(
                ShardSpec::with_range(s2.clone(), e2.clone()),
                ShardSpec::with_range(e2, vec![0xFF; 32]),
            );
            prop_assume!(plan1 != plan2);
            prop_assert_ne!(hash_split_residual_payload(&plan1), hash_split_residual_payload(&plan2));
        }

        // Purity: split-replace.
        #[test]
        fn hash_split_replace_is_pure(
            start in proptest::collection::vec(any::<u8>(), 1..16),
            suffix in proptest::collection::vec(any::<u8>(), 1..8),
        ) {
            let mut mid = start.clone();
            mid.extend_from_slice(&suffix);
            let plan = SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(ShardSpec::with_range(start, mid.clone()), Cursor::initial()),
                SplitReplaceChild::new(ShardSpec::with_range(mid, vec![0xFF; 32]), Cursor::initial()),
            ]).unwrap();
            prop_assert_eq!(hash_split_replace_payload(&plan), hash_split_replace_payload(&plan));
        }

        // Purity: split-residual.
        #[test]
        fn hash_split_residual_is_pure(
            start in proptest::collection::vec(any::<u8>(), 1..16),
            suffix in proptest::collection::vec(any::<u8>(), 1..8),
        ) {
            let mut mid = start.clone();
            mid.extend_from_slice(&suffix);
            let plan = SplitResidualPlan::new(
                ShardSpec::with_range(start, mid.clone()),
                ShardSpec::with_range(mid, vec![0xFF; 32]),
            );
            prop_assert_eq!(hash_split_residual_payload(&plan), hash_split_residual_payload(&plan));
        }
    }
}
