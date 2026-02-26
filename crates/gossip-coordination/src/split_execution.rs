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
//! ## Planning vs Execution
//!
//! Split-replace planner mechanics (plan types and `plan_split_replace*`
//! constructors) are owned by
//! [`gossip_contracts::coordination::split`]. This module owns
//! coordination-layer split execution support: derived IDs, payload hashes,
//! and split-residual plan/result types used directly by the backend.
//!
//! This module intentionally does not own full split precondition validation.
//! Backend implementations validate live-state invariants (lease/fence
//! validity, spawn limits, and derived-ID collision checks) before mutating
//! records.
//!
//! Child cursors in split-replace plans are passed through as payload and are
//! not re-validated against child specs at execution time.
//!
//! ## Derived Shard IDs
//!
//! Derived shard IDs have bit 63 set — distinguishing root shards
//! (externally assigned) from split-derived shards (deterministically
//! computed). Birthday collision bound ~2^31.5 values before 50%
//! collision probability (63 effective bits); acceptable for bounded
//! coordination use cases.
//!
//! ## Payload Hashing
//!
//! Payload hashes use domain-separated BLAKE3 with [`CanonicalBytes`]
//! encoding. This ties the op-log idempotency check to the actual
//! operation parameters, detecting "same OpId, different payload"
//! conflicts. Each operation type (`checkpoint`, `complete`, `park`,
//! `split_replace`, `split_residual`) gets a distinct `op_tag` byte
//! string as a secondary domain-separation layer within the shared
//! `OP_PAYLOAD_V1` domain. Hash helpers are intentionally pure and do not
//! validate protocol preconditions.

use std::fmt;

use blake3::Hasher;
use gossip_stdx::InlineVec;

use crate::record::ParkReason;
#[cfg(test)]
use gossip_contracts::coordination::cursor::CursorUpdate;
#[cfg(test)]
use gossip_contracts::coordination::shard_spec::ShardSpec;
use gossip_contracts::coordination::shard_spec::ShardSpecRef;
use gossip_contracts::coordination::split::SplitReplacePlan;
#[cfg(test)]
use gossip_contracts::coordination::split::{
    SplitReplaceChild, plan_split_replace_at_points_initial_cursor,
};
use gossip_contracts::identity::hashing::{OP_PAYLOAD_HASHER, SPLIT_ID_HASHER};
use gossip_contracts::identity::{CanonicalBytes, OpId, RunId, ShardId, finalize_64};

// ============================================================================
// Constants
// ============================================================================

use gossip_contracts::coordination::limits::MAX_SPLIT_CHILDREN;

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
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Child),
            1 => Some(Self::Residual),
            _ => None,
        }
    }

    /// Return the stable `u8` discriminant.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for DerivedShardKind {
    /// Delegates to the `u8` discriminant -- single-byte, fixed-width encoding.
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
// Split-replace planning
// ============================================================================
//
// Split-replace planner types and constructors live in
// `gossip_contracts::coordination::split`. This module consumes those types
// for payload hashing and backend execution.

// ============================================================================
// SplitResidualPlan
// ============================================================================

/// Plan for a split-residual operation: parent shrinks its key range and
/// a new residual shard covers the remainder.
///
/// ```text
/// Before:  parent [────────────────────────)
///                  ^cursor here
///
/// After:   parent [──────────)              ← keeps scanning (Active)
///                  ^cursor    residual [────) ← new shard, initial cursor
/// ```
///
/// The parent keeps `parent_new_spec` (the prefix it has already partially
/// scanned) and continues processing with its existing lease. The residual
/// shard gets `residual_spec` (the unprocessed suffix) and starts from
/// `CursorUpdate::initial()` (enforced by the coordinator, not by this type).
///
/// ## Key Difference from Split-Replace
///
/// Split-replace is terminal for the parent (status -> Split). Split-residual
/// is non-terminal: the parent stays Active with a narrowed range. This makes
/// split-residual the right choice when a worker wants to shed its tail
/// while continuing to process its prefix.
///
/// ## Coverage Contract
///
/// `parent_new_spec union residual_spec` must equal the parent's original
/// `ShardSpec` range, with no overlap. This is enforced by the coordinator
/// at execution time via [`validate_residual_split`](gossip_contracts::coordination::shard_spec::validate_residual_split),
/// not by this plan type.
///
/// ## Intentional Minimalism
///
/// This type carries only target specs so call sites can stage a residual
/// operation without needing mutable access to live parent state. Invariants
/// that depend on live state (for example, parent cursor remaining in-bounds
/// after shrink) are validated by backend execution code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResidualPlan<'a> {
    parent_new_spec: ShardSpecRef<'a>,
    residual_spec: ShardSpecRef<'a>,
}

/// Error returned when a [`SplitResidualPlan`] is constructed with
/// identical specs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitResidualPlanError {
    /// `parent_new_spec` and `residual_spec` are identical — a residual
    /// split must actually shrink the parent and produce a distinct range.
    IdenticalSpecs,
}

impl fmt::Display for SplitResidualPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdenticalSpecs => {
                write!(
                    f,
                    "split-residual requires parent_new_spec and residual_spec to differ"
                )
            }
        }
    }
}

impl std::error::Error for SplitResidualPlanError {}

impl<'a> SplitResidualPlan<'a> {
    /// Construct a residual plan with a minimal structural guard.
    ///
    /// The only check performed here is that the two specs differ
    /// (identical specs would mean no actual split occurred). The full
    /// coverage contract — `parent_new_spec ∪ residual_spec` equals the
    /// original parent range with no overlap — is enforced by the
    /// coordinator at execution time via
    /// [`validate_residual_split`](gossip_contracts::coordination::shard_spec::validate_residual_split).
    ///
    /// # Errors
    ///
    /// Returns [`SplitResidualPlanError::IdenticalSpecs`] if
    /// `parent_new_spec == residual_spec`.
    pub fn try_new(
        parent_new_spec: ShardSpecRef<'a>,
        residual_spec: ShardSpecRef<'a>,
    ) -> Result<Self, SplitResidualPlanError> {
        if parent_new_spec == residual_spec {
            return Err(SplitResidualPlanError::IdenticalSpecs);
        }
        Ok(Self {
            parent_new_spec,
            residual_spec,
        })
    }

    /// The parent's new (shrunk) specification — the range it keeps.
    #[inline]
    #[must_use]
    pub fn parent_new_spec(&self) -> ShardSpecRef<'a> {
        self.parent_new_spec
    }

    /// The residual shard's specification — the range split off.
    #[inline]
    #[must_use]
    pub fn residual_spec(&self) -> ShardSpecRef<'a> {
        self.residual_spec
    }
}

impl CanonicalBytes for SplitResidualPlan<'_> {
    /// Encodes `parent_new_spec || residual_spec` in that order.
    ///
    /// No length prefix is needed because a residual plan always has exactly
    /// two fixed-position fields, so the boundary is unambiguous.
    fn write_canonical(&self, h: &mut Hasher) {
        self.parent_new_spec.write_canonical(h);
        self.residual_spec.write_canonical(h);
    }
}

// ============================================================================
// Split operation result types
// ============================================================================

/// Result of a successful `split_replace` operation.
///
/// Contains the deterministically-derived child shard IDs, ordered by
/// `key_range_start` for reproducibility (same inputs produce the same
/// order). IDs are derived via [`derive_split_shard_id`] with
/// `DerivedShardKind::Child` and sequential indices.
///
/// On idempotent replay, the coordinator returns the same result without
/// creating duplicate children — the op-log entry proves the split already
/// executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplaceResult {
    /// Deterministically-derived child shard IDs, ordered by `key_range_start`
    /// for reproducibility (same inputs always produce the same order).
    pub children: InlineVec<ShardId, MAX_SPLIT_CHILDREN>,
}

/// Result of a successful `split_residual` operation.
///
/// Contains the deterministically-derived residual shard ID, produced by
/// [`derive_split_shard_id`] with `DerivedShardKind::Residual`.
///
/// On idempotent replay, the coordinator returns the same residual ID
/// without creating a duplicate shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResidualResult {
    /// Deterministically-derived residual shard ID covering the unprocessed
    /// upper portion of the parent's original key range.
    pub residual: ShardId,
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
/// BLAKE3 truncated to 64 bits with bit 63 forced gives 63 effective
/// bits of entropy. Birthday collision probability reaches ~50% at
/// ~2^31.5 derived IDs. This is acceptable for coordination use cases
/// where the total number of derived shards per run is bounded by
/// [`MAX_SPAWNED_PER_SHARD`](gossip_contracts::coordination::limits::MAX_SPAWNED_PER_SHARD) × shard count.
///
/// ## Caller Responsibility
///
/// The `index` parameter must be a unique, deterministic position in the
/// parent-derived sequence for this operation (for example
/// `base_spawned_len + child_offset`). Using the same index for two
/// siblings of the same split produces identical IDs — all other hash
/// inputs (`run`, `parent`, `op`, `kind`) are shared, so `index` is the
/// only discriminator between siblings. This is not enforced at the
/// call site; correctness depends on the caller supplying distinct
/// indices.
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

    // Force bit 63 so ShardId::is_derived() returns true, distinguishing
    // this ID from externally-assigned root shard IDs (which have bit 63
    // clear). This reduces effective entropy from 64 to 63 bits.
    let id = finalize_64(&h) | (1u64 << 63);
    let result = ShardId::from_raw(id);
    assert!(result.is_derived(), "derived shard ID must have bit 63 set");
    assert!(result.as_raw() != 0, "derived shard ID must be non-zero");
    result
}

// ============================================================================
// Payload hash functions
// ============================================================================
//
// Every coordinator mutation (checkpoint, complete, park, split-replace,
// split-residual) fingerprints its parameters into a 64-bit payload hash
// stored alongside the OpId in the shard's op-log. On idempotent replay,
// the coordinator compares the stored hash against the incoming payload to
// detect "same OpId, different parameters" conflicts.
//
// All hash functions below are thin wrappers around `op_payload_hash`,
// differing only in their `op_tag` and the fields they encode.

/// Shared implementation for all payload hash functions.
///
/// Clones the cached `OP_PAYLOAD_HASHER` (`OP_PAYLOAD_V1` domain),
/// prepends the operation-specific `op_tag`, then delegates to
/// `write_fields` for the operation's canonical payload.
///
/// The `op_tag` acts as a secondary domain-separation layer within the
/// shared `OP_PAYLOAD_V1` domain: even if two different operation types
/// happen to produce identical field bytes, the different tags guarantee
/// distinct hashes (verified by `checkpoint_and_complete_hashes_differ`
/// property test).
#[must_use]
pub fn op_payload_hash(op_tag: &[u8], write_fields: impl FnOnce(&mut Hasher)) -> u64 {
    let mut h = OP_PAYLOAD_HASHER.clone();
    h.update(op_tag);
    write_fields(&mut h);
    finalize_64(&h)
}

/// Payload hash for a checkpoint operation.
///
/// Stored in the op-log alongside the [`OpId`] to detect "same OpId,
/// different cursor" conflicts during idempotent replay.
///
/// Accepts any cursor representation with canonical bytes (for example,
/// borrowed [`gossip_contracts::coordination::cursor::CursorUpdate`] or any
/// equivalent canonical representation).
#[must_use]
pub fn hash_checkpoint_payload(new_cursor: &impl CanonicalBytes) -> u64 {
    op_payload_hash(b"checkpoint", |h| {
        new_cursor.write_canonical(h);
    })
}

/// Payload hash for a complete operation.
///
/// Same role as [`hash_checkpoint_payload`] but for the terminal
/// completion event. The `b"complete"` tag ensures a completion and
/// a checkpoint with the same cursor produce different hashes.
///
/// Uses the same canonical-byte requirement as [`hash_checkpoint_payload`]
/// so all cursor encodings with equivalent canonical bytes hash identically.
#[must_use]
pub fn hash_complete_payload(final_cursor: &impl CanonicalBytes) -> u64 {
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
pub fn hash_split_replace_payload(plan: &SplitReplacePlan<'_>) -> u64 {
    op_payload_hash(b"split_replace", |h| {
        plan.write_canonical(h);
    })
}

/// Payload hash for a split-residual operation.
///
/// Fingerprints both the parent's new spec and the residual spec for
/// op-log idempotency.
#[must_use]
pub fn hash_split_residual_payload(plan: &SplitResidualPlan<'_>) -> u64 {
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
    use gossip_contracts::test_util::canonical_digest;
    use proptest::prelude::*;

    // -- Golden test vectors --

    /// `derive_split_shard_id(run=1, parent=100, op=999, Child, 0)`.
    const DERIVE_SPLIT_CHILD_0_EXPECTED: u64 = 0xada8_c6fc_a389_4936;
    /// `derive_split_shard_id(run=1, parent=100, op=999, Child, 1)`.
    const DERIVE_SPLIT_CHILD_1_EXPECTED: u64 = 0xac88_444c_76bd_fa28;
    /// `derive_split_shard_id(run=1, parent=100, op=999, Residual, 0)`.
    const DERIVE_SPLIT_RESIDUAL_EXPECTED: u64 = 0xfea1_0675_fdf7_8c46;
    /// `hash_checkpoint_payload` with cursor last_key `b"golden-cursor-key"`.
    const HASH_CHECKPOINT_EXPECTED: u64 = 0x0806_b9d3_83fd_8430;
    /// `hash_complete_payload` with cursor last_key `b"golden-cursor-key"`.
    const HASH_COMPLETE_EXPECTED: u64 = 0x9a83_e072_185a_bf89;
    /// `hash_park_payload(ParkReason::Poisoned)`.
    const HASH_PARK_EXPECTED: u64 = 0xf0e5_baaa_11b5_6d8d;
    /// `hash_split_replace_payload` with `[a,m) + [m,z)` children, initial cursors.
    const HASH_SPLIT_REPLACE_EXPECTED: u64 = 0xa592_eea6_db2f_cb49;
    /// `hash_split_residual_payload` with parent_new `[a,m)`, residual `[m,z)`.
    const HASH_SPLIT_RESIDUAL_EXPECTED: u64 = 0x4be2_bdea_6344_7e13;

    // Compile-time assertion: all derived shard ID golden values have bit 63 set.
    const _: () = assert!(DERIVE_SPLIT_CHILD_0_EXPECTED & (1u64 << 63) != 0);
    const _: () = assert!(DERIVE_SPLIT_CHILD_1_EXPECTED & (1u64 << 63) != 0);
    const _: () = assert!(DERIVE_SPLIT_RESIDUAL_EXPECTED & (1u64 << 63) != 0);

    // -- Coordination golden vectors ----------------------------------------

    #[test]
    fn derive_split_shard_id_golden_values() {
        use gossip_contracts::identity::{OpId, RunId, ShardId};

        let cases: &[(DerivedShardKind, u32, u64)] = &[
            (DerivedShardKind::Child, 0, DERIVE_SPLIT_CHILD_0_EXPECTED),
            (DerivedShardKind::Child, 1, DERIVE_SPLIT_CHILD_1_EXPECTED),
            (
                DerivedShardKind::Residual,
                0,
                DERIVE_SPLIT_RESIDUAL_EXPECTED,
            ),
        ];
        for &(kind, index, expected) in cases {
            let id = derive_split_shard_id(
                RunId::from_raw(1),
                ShardId::from_raw(100),
                OpId::from_raw(999),
                kind,
                index,
            );
            assert_eq!(
                id.as_raw(),
                expected,
                "derive_split_shard_id({kind:?}, {index}) golden vector changed \
                 (domain::SPLIT_ID_V1).\nActual: {:#018x}",
                id.as_raw(),
            );
        }
    }

    #[test]
    fn hash_checkpoint_golden_value() {
        use gossip_contracts::coordination::cursor::CursorUpdate;

        let cursor = CursorUpdate::with_last_key(b"golden-cursor-key");
        let hash = hash_checkpoint_payload(&cursor);
        assert_eq!(
            hash, HASH_CHECKPOINT_EXPECTED,
            "hash_checkpoint_payload golden vector changed (domain::OP_PAYLOAD_V1).\n\
             Actual: {hash:#018x}",
        );
    }

    #[test]
    fn hash_complete_golden_value() {
        use gossip_contracts::coordination::cursor::CursorUpdate;

        let cursor = CursorUpdate::with_last_key(b"golden-cursor-key");
        let hash = hash_complete_payload(&cursor);
        assert_eq!(
            hash, HASH_COMPLETE_EXPECTED,
            "hash_complete_payload golden vector changed (domain::OP_PAYLOAD_V1).\n\
             Actual: {hash:#018x}",
        );
    }

    #[test]
    fn hash_park_golden_value() {
        let hash = hash_park_payload(ParkReason::Poisoned);
        assert_eq!(
            hash, HASH_PARK_EXPECTED,
            "hash_park_payload(Poisoned) golden vector changed (domain::OP_PAYLOAD_V1).\n\
             Actual: {hash:#018x}",
        );
    }

    #[test]
    fn hash_split_replace_golden_value() {
        use gossip_contracts::coordination::cursor::CursorUpdate;

        let spec1 = ShardSpec::with_range(b"a", b"m");
        let spec2 = ShardSpec::with_range(b"m", b"z");
        let cursor1 = CursorUpdate::initial();
        let cursor2 = CursorUpdate::initial();
        let c1 = SplitReplaceChild::new(spec1.as_ref(), cursor1);
        let c2 = SplitReplaceChild::new(spec2.as_ref(), cursor2);
        let plan = SplitReplacePlan::try_new(vec![c1, c2]).unwrap();
        let hash = hash_split_replace_payload(&plan);
        assert_eq!(
            hash, HASH_SPLIT_REPLACE_EXPECTED,
            "hash_split_replace_payload golden vector changed (domain::OP_PAYLOAD_V1).\n\
             Actual: {hash:#018x}",
        );
    }

    #[test]
    fn hash_split_residual_golden_value() {
        let parent_new = ShardSpec::with_range(b"a", b"m");
        let residual = ShardSpec::with_range(b"m", b"z");
        let plan = SplitResidualPlan::try_new(parent_new.as_ref(), residual.as_ref()).unwrap();
        let hash = hash_split_residual_payload(&plan);
        assert_eq!(
            hash, HASH_SPLIT_RESIDUAL_EXPECTED,
            "hash_split_residual_payload golden vector changed (domain::OP_PAYLOAD_V1).\n\
             Actual: {hash:#018x}",
        );
    }

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

    // -- Execution-layer hash determinism --------------------------------

    /// Verify that `hash_split_replace_payload` produces identical hashes for
    /// identical plans. Planner correctness is tested in `gossip-contracts`.
    #[test]
    fn hash_split_replace_payload_deterministic_across_identical_plans() {
        let parent = ShardSpec::with_range_and_metadata(b"a", b"z", b"meta");
        let split_points = [b"m".as_slice()];

        let plan_a =
            plan_split_replace_at_points_initial_cursor(parent.as_ref(), split_points).unwrap();
        let plan_b =
            plan_split_replace_at_points_initial_cursor(parent.as_ref(), split_points).unwrap();

        assert_eq!(
            hash_split_replace_payload(&plan_a),
            hash_split_replace_payload(&plan_b),
            "identical plans must produce identical payload hashes"
        );
    }

    // -- SplitResidualPlan validation ------------------------------------

    #[test]
    fn split_residual_plan_valid() {
        let parent = ShardSpec::with_range(b"a", b"m");
        let residual = ShardSpec::with_range(b"m", b"z");
        let plan = SplitResidualPlan::try_new(parent.as_ref(), residual.as_ref()).unwrap();
        assert_eq!(plan.parent_new_spec(), parent.as_ref());
        assert_eq!(plan.residual_spec(), residual.as_ref());
    }

    #[test]
    fn split_residual_plan_identical_specs_returns_error() {
        let spec = ShardSpec::with_range(b"a", b"z");
        assert_eq!(
            SplitResidualPlan::try_new(spec.as_ref(), spec.as_ref()),
            Err(SplitResidualPlanError::IdenticalSpecs),
        );
    }

    // -- CanonicalBytes --------------------------------------------------

    #[test]
    fn split_replace_plan_canonical_deterministic() {
        let spec1 = ShardSpec::with_range(b"a", b"m");
        let spec2 = ShardSpec::with_range(b"m", b"z");
        let c1 = CursorUpdate::initial();
        let c2 = CursorUpdate::initial();
        let c1 = SplitReplaceChild::new(spec1.as_ref(), c1);
        let c2 = SplitReplaceChild::new(spec2.as_ref(), c2);
        let plan = SplitReplacePlan::try_new(vec![c1, c2]).unwrap();
        assert_eq!(canonical_digest(&plan), canonical_digest(&plan));
    }

    // -- Property tests --------------------------------------------------

    proptest! {
        #![proptest_config(gossip_contracts::test_util::miri_proptest_config())]

        // Distinct input tuples should map to distinct derived shard IDs in
        // practice (hash collisions are astronomically unlikely).
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

        // Derived IDs always have bit 63 set + same inputs → same output.
        #[test]
        fn derive_split_shard_id_derived_and_pure(
            run in any::<u64>(), parent in any::<u64>(), op in any::<u64>(),
            kind in 0u8..2, index in any::<u32>(),
        ) {
            let k = DerivedShardKind::from_u8(kind).unwrap();
            let a = derive_split_shard_id(RunId::from_raw(run), ShardId::from_raw(parent), OpId::from_raw(op), k, index);
            let b = derive_split_shard_id(RunId::from_raw(run), ShardId::from_raw(parent), OpId::from_raw(op), k, index);
            prop_assert!(a.is_derived());
            prop_assert_eq!(a, b);
        }

        // Cursor-based hash collision-freedom (checkpoint and complete).
        #[test]
        fn cursor_hash_collision_free(
            k1 in proptest::collection::vec(any::<u8>(), 1..64),
            k2 in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            prop_assume!(k1 != k2);
            let c1 = CursorUpdate::with_last_key(&k1);
            let c2 = CursorUpdate::with_last_key(&k2);
            prop_assert_ne!(hash_checkpoint_payload(&c1), hash_checkpoint_payload(&c2));
            prop_assert_ne!(hash_complete_payload(&c1), hash_complete_payload(&c2));
        }

        // Cursor-based hash purity (checkpoint and complete).
        #[test]
        fn cursor_hash_functions_are_pure(
            k in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let c = CursorUpdate::with_last_key(&k);
            prop_assert_eq!(hash_checkpoint_payload(&c), hash_checkpoint_payload(&c));
            prop_assert_eq!(hash_complete_payload(&c), hash_complete_payload(&c));
        }

        // Domain separation: checkpoint and complete produce different hashes
        // for any cursor. Subsumes the former point-check unit test.
        #[test]
        fn checkpoint_and_complete_hashes_differ(
            k in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let c = CursorUpdate::with_last_key(&k);
            prop_assert_ne!(hash_checkpoint_payload(&c), hash_complete_payload(&c));
        }

        // Park hash: collision-free.
        #[test]
        fn hash_park_collision_free(a in 0u8..5, b in 0u8..5) {
            prop_assume!(a != b);
            let ra = ParkReason::from_u8(a).unwrap();
            let rb = ParkReason::from_u8(b).unwrap();
            prop_assert_ne!(hash_park_payload(ra), hash_park_payload(rb));
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

            let spec1_a = ShardSpec::with_range(s1.clone(), e1.clone());
            let spec1_b = ShardSpec::with_range(e1, vec![0xFF; 32]);
            let spec2_a = ShardSpec::with_range(s2.clone(), e2.clone());
            let spec2_b = ShardSpec::with_range(e2, vec![0xFF; 32]);
            let c1_a = CursorUpdate::initial();
            let c1_b = CursorUpdate::initial();
            let c2_a = CursorUpdate::initial();
            let c2_b = CursorUpdate::initial();
            let plan1 = SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(spec1_a.as_ref(), c1_a),
                SplitReplaceChild::new(spec1_b.as_ref(), c1_b),
            ]).unwrap();
            let plan2 = SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(spec2_a.as_ref(), c2_a),
                SplitReplaceChild::new(spec2_b.as_ref(), c2_b),
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

            let plan1_parent = ShardSpec::with_range(s1.clone(), e1.clone());
            let plan1_residual = ShardSpec::with_range(e1, vec![0xFF; 32]);
            let plan1 = SplitResidualPlan::try_new(
                plan1_parent.as_ref(),
                plan1_residual.as_ref(),
            ).unwrap();
            let plan2_parent = ShardSpec::with_range(s2.clone(), e2.clone());
            let plan2_residual = ShardSpec::with_range(e2, vec![0xFF; 32]);
            let plan2 = SplitResidualPlan::try_new(
                plan2_parent.as_ref(),
                plan2_residual.as_ref(),
            ).unwrap();
            prop_assume!(plan1 != plan2);
            prop_assert_ne!(hash_split_residual_payload(&plan1), hash_split_residual_payload(&plan2));
        }

    }
}
