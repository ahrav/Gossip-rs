//! Backend-agnostic split planning for shard key-range subdivision.
//!
//! When a shard's key range grows too large or its workload becomes skewed,
//! the coordinator subdivides it. This module provides the *planning* layer:
//! it validates geometric constraints and produces an immutable plan value
//! that downstream execution logic can apply atomically.
//!
//! # Two Split Strategies
//!
//! **Split-replace** ([`SplitReplacePlan`]): the parent shard is retired and
//! replaced by two or more children whose key ranges form a contiguous
//! partition of the parent's `[start, end)` interval. Use this when the
//! parent range should be evenly (or intentionally unevenly) subdivided
//! with the parent ceasing to exist.
//!
//! **Split-residual** ([`SplitResidualPlan`]): the parent shrinks its key
//! range in place and a new *residual* shard covers the removed tail. Use
//! this when a worker has made forward progress through a prefix of the
//! range and should keep owning the already-scanned prefix while the
//! unprocessed tail is offloaded. [`plan_split_residual_from_cursor`]
//! derives the split point automatically from the worker's cursor position.
//!
//! # Planning vs Execution
//!
//! - **This module** owns shape validation (fan-out bounds), cursor-to-
//!   split-point derivation, and orchestrates coverage validation by
//!   calling [`crate::coordination::shard_spec::validate_split_coverage_bounds`] /
//!   [`validate_residual_split`]
//!   (defined in `shard_spec.rs`).
//! - **`gossip-coordination::split_execution`** owns execution-time
//!   concerns: derived shard IDs, payload hashing for op-log idempotency,
//!   and result types consumed by backends.
//! - **Backend implementations** enforce live-state preconditions that
//!   require mutable coordinator state: lease/fence validity, spawn-limit
//!   enforcement, derived-ID collision detection, and record mutation
//!   ordering.
//!
//! # Design: Borrowed Views
//!
//! All plan types are parameterized by lifetime `'a` and operate on
//! [`ShardSpecRef`] / [`CursorUpdate`] borrows. This lets callers build
//! plans from stack-local or slab-backed storage without intermediate
//! heap allocation, consistent with the project's tiered allocation
//! policy (HOT path = allocation-silent where practical).

use crate::coordination::cursor::{CursorUpdate, MAX_KEY_SIZE, key_successor_into};
use crate::coordination::limits::MAX_SPLIT_CHILDREN;
use crate::coordination::shard_spec::{
    ShardSpecRef, SplitValidationError, validate_residual_split, validate_split_coverage_bounds,
};
use crate::identity::CanonicalBytes;
use blake3::Hasher;
use gossip_stdx::InlineVec;

/// A single child in a [`SplitReplacePlan`].
///
/// Pairs a key sub-range ([`ShardSpecRef`]) with an initial cursor position
/// ([`CursorUpdate`]) that tells the new shard where to begin scanning.
///
/// ## Cursor Passthrough
///
/// The planner carries cursor payloads through unchanged and does not
/// validate cursor semantics against live shard state. Execution likewise
/// treats child cursors as opaque plan payload -- it validates shape and
/// coverage but does not re-check cursor bounds against child specs.
/// Callers are responsible for constructing meaningful child cursors
/// (e.g., `CursorUpdate::initial()` for fresh starts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitReplaceChild<'a> {
    spec: ShardSpecRef<'a>,
    cursor: CursorUpdate<'a>,
}

impl<'a> SplitReplaceChild<'a> {
    /// Initializes a child configuration for a split-replace operation.
    #[must_use]
    pub fn new(spec: ShardSpecRef<'a>, cursor: CursorUpdate<'a>) -> Self {
        Self { spec, cursor }
    }

    /// Returns the assigned key sub-range for this child.
    #[inline]
    #[must_use]
    pub fn spec(&self) -> ShardSpecRef<'a> {
        self.spec
    }

    /// Returns the scanning origin point for this child.
    #[inline]
    #[must_use]
    pub fn cursor(&self) -> CursorUpdate<'a> {
        self.cursor
    }
}

impl CanonicalBytes for SplitReplaceChild<'_> {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.spec.write_canonical(h);
        self.cursor.write_canonical(h);
    }
}

/// Validated plan for a split-replace operation.
///
/// A split-replace retires the parent shard and replaces it with >= 2
/// children whose key ranges collectively cover the parent's `[start, end)`
/// interval with no gaps and no overlaps.
///
/// ## Child Ordering
///
/// Children are stored in caller-provided order. Coverage validation sorts
/// internally by `key_range_start`, but canonical encoding and payload
/// hashing preserve the original order. Callers that need order-stable
/// hashes across retries should supply children in a deterministic sequence.
///
/// ## Storage
///
/// Backed by [`InlineVec`] with capacity [`MAX_SPLIT_CHILDREN`] (256).
/// Plans up to that limit remain stack-allocated; exceeding the limit is
/// rejected before allocation occurs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplacePlan<'a> {
    children: InlineVec<SplitReplaceChild<'a>, MAX_SPLIT_CHILDREN>,
}

/// Indicates an invalid child count during split-replace planning.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SplitReplacePlanError {
    /// Fewer than 2 children — not a split.
    #[error("split-replace requires >= 2 children, got {count}")]
    TooFewChildren { count: usize },
    /// More than [`MAX_SPLIT_CHILDREN`] children.
    ///
    /// `count` is a lower bound: the iterator is not fully consumed once
    /// the limit is exceeded, so the actual count may be higher.
    #[error("split-replace exceeds max children ({count} > {MAX_SPLIT_CHILDREN})")]
    TooManyChildren { count: usize },
}

impl<'a> SplitReplacePlan<'a> {
    /// Validates structural fan-out bounds for a split-replace plan.
    ///
    /// This constructor enforces only shape invariants (fan-out bounds). It
    /// does not validate parent-range coverage; use [`plan_split_replace`] for
    /// full geometric validation against a parent shard.
    ///
    /// # Errors
    ///
    /// Returns [`SplitReplacePlanError`] if `children.len() < 2` or
    /// `children.len() > MAX_SPLIT_CHILDREN`.
    pub fn try_new(
        children: impl IntoIterator<Item = SplitReplaceChild<'a>>,
    ) -> Result<Self, SplitReplacePlanError> {
        let mut collected = InlineVec::new();
        for child in children {
            if collected.len() == MAX_SPLIT_CHILDREN {
                return Err(SplitReplacePlanError::TooManyChildren {
                    count: MAX_SPLIT_CHILDREN + 1,
                });
            }
            collected.push(child);
        }
        if collected.len() < 2 {
            return Err(SplitReplacePlanError::TooFewChildren {
                count: collected.len(),
            });
        }
        Ok(Self {
            children: collected,
        })
    }

    /// Returns the ordered sequence of child configurations.
    #[inline]
    #[must_use]
    pub fn children(&self) -> &[SplitReplaceChild<'a>] {
        self.children.as_slice()
    }
}

// Guarantees the u32 cast in `write_canonical` cannot overflow.
const _: () = assert!(MAX_SPLIT_CHILDREN <= u32::MAX as usize);

impl CanonicalBytes for SplitReplacePlan<'_> {
    /// Encodes `len(children) || child[0] || child[1] || ...` using a
    /// length-prefixed scheme so the hash boundary between plans of
    /// different sizes is unambiguous.
    fn write_canonical(&self, h: &mut Hasher) {
        u32::try_from(self.children.len())
            .expect("child count exceeds u32")
            .write_canonical(h);
        for child in &self.children {
            child.write_canonical(h);
        }
    }
}

/// Failures occurring during split-replace derivation.
///
/// Distinguishes shape errors (invalid child count) from semantic errors
/// (children do not form a valid partition of the parent range).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SplitReplacePlanningError {
    /// Plan child-count invariants failed (`< 2` or `> MAX_SPLIT_CHILDREN`).
    #[error("{0}")]
    InvalidChildCount(#[source] SplitReplacePlanError),
    /// Child ranges failed split coverage validation against the parent.
    #[error("{0}")]
    InvalidCoverage(#[source] SplitValidationError),
}

/// Derives a split-replace plan, validating comprehensive coverage of the parent shard.
///
/// This helper enforces both child-count bounds and full coverage
/// correctness via [`crate::coordination::shard_spec::validate_split_coverage_bounds`].
///
/// Coverage validation treats children as an unordered set (sorted internally
/// by `key_range_start`), but the returned plan keeps original child order.
///
/// # Errors
///
/// - [`SplitReplacePlanningError::InvalidChildCount`] if fewer than 2 or
///   more than [`MAX_SPLIT_CHILDREN`] children are provided.
/// - [`SplitReplacePlanningError::InvalidCoverage`] if children fail
///   partition validation against `parent`.
pub fn plan_split_replace<'a>(
    parent: ShardSpecRef<'a>,
    children: impl IntoIterator<Item = SplitReplaceChild<'a>>,
) -> Result<SplitReplacePlan<'a>, SplitReplacePlanningError> {
    let plan = SplitReplacePlan::try_new(children)
        .map_err(SplitReplacePlanningError::InvalidChildCount)?;
    let mut child_specs: InlineVec<ShardSpecRef<'a>, MAX_SPLIT_CHILDREN> = InlineVec::new();
    for child in plan.children() {
        child_specs.push(child.spec());
    }
    validate_split_coverage_bounds(
        parent.key_range_start(),
        parent.key_range_end(),
        child_specs.as_slice(),
    )
    .map_err(SplitReplacePlanningError::InvalidCoverage)?;
    Ok(plan)
}

/// Derives a split-replace plan from discrete internal boundary markers.
///
/// Split points define child boundaries over the parent range:
/// `[start, p0), [p0, p1), ..., [pn, end)`.
///
/// `split_points` are interpreted in iterator order. Out-of-order or duplicate
/// points are rejected by final coverage validation.
///
/// The function preflights fan-out before materializing children or invoking
/// `cursor_for_child`; if `MAX_SPLIT_CHILDREN` would be exceeded, the callback
/// is never called.
///
/// # Errors
///
/// - [`SplitReplacePlanningError::InvalidChildCount`] when split-point fan-out
///   would exceed [`MAX_SPLIT_CHILDREN`] children, or when no split points
///   produce only one child.
/// - [`SplitReplacePlanningError::InvalidCoverage`] when points do not form a
///   valid partition of `parent`.
pub fn plan_split_replace_at_points<'a>(
    parent: ShardSpecRef<'a>,
    split_points: impl IntoIterator<Item = &'a [u8]>,
    mut cursor_for_child: impl FnMut(usize, ShardSpecRef<'a>) -> CursorUpdate<'a>,
) -> Result<SplitReplacePlan<'a>, SplitReplacePlanningError> {
    let mut points: InlineVec<&'a [u8], MAX_SPLIT_CHILDREN> = InlineVec::new();
    for point in split_points {
        // N split points produce N+1 children (N intervals plus the tail).
        if points.len() + 2 > MAX_SPLIT_CHILDREN {
            return Err(SplitReplacePlanningError::InvalidChildCount(
                SplitReplacePlanError::TooManyChildren {
                    count: MAX_SPLIT_CHILDREN + 1,
                },
            ));
        }
        points.push(point);
    }

    let mut children: InlineVec<SplitReplaceChild<'a>, MAX_SPLIT_CHILDREN> = InlineVec::new();
    let mut child_start = parent.key_range_start();
    for (index, point) in points.into_iter().enumerate() {
        let spec = ShardSpecRef::new(child_start, point, parent.metadata());
        let cursor = cursor_for_child(index, spec);
        children.push(SplitReplaceChild::new(spec, cursor));
        child_start = point;
    }

    let tail_index = children.len();
    let tail_spec = ShardSpecRef::new(child_start, parent.key_range_end(), parent.metadata());
    let tail_cursor = cursor_for_child(tail_index, tail_spec);
    children.push(SplitReplaceChild::new(tail_spec, tail_cursor));

    plan_split_replace(parent, children.as_slice().iter().copied())
}

/// Derives a split-replace plan, initializing all child cursors to their starting positions.
///
/// # Errors
///
/// Propagates [`SplitReplacePlanningError`] from
/// [`plan_split_replace_at_points`].
pub fn plan_split_replace_at_points_initial_cursor<'a>(
    parent: ShardSpecRef<'a>,
    split_points: impl IntoIterator<Item = &'a [u8]>,
) -> Result<SplitReplacePlan<'a>, SplitReplacePlanningError> {
    plan_split_replace_at_points(parent, split_points, |_, _| CursorUpdate::initial())
}

// Split-residual planning

/// Validated plan for a split-residual operation.
///
/// The parent shard shrinks its key range in place and a new *residual*
/// shard is created to cover the removed suffix.
///
/// ```text
/// Before:  parent [────────────────────────)
///                  ^cursor
///
/// After:   parent [──────────)              <-- keeps scanning (Active)
///                  ^cursor    residual [────) <-- new shard, initial cursor
/// ```
///
/// ## Asymmetry with Split-Replace
///
/// Split-replace is terminal for the parent (its status transitions to
/// `Split`). Split-residual is non-terminal: the parent stays `Active`
/// with a narrowed range. This makes split-residual the right choice when
/// a worker wants to shed its tail while continuing to process its prefix.
///
/// ## Coverage Contract
///
/// `parent_new_spec` union `residual_spec` must equal the parent's original
/// range with no gap and no overlap. The planning free functions
/// ([`plan_split_residual`], [`plan_split_residual_at_point`],
/// [`plan_split_residual_from_cursor`]) enforce this via
/// [`validate_residual_split`]. The plan type itself (`try_new`) checks
/// only that the two specs are not identical (a degenerate no-op), so
/// callers bypassing the planning helpers must validate coverage themselves.
///
/// ## Intentional Minimalism
///
/// This type carries only the target specs, so callers can stage a
/// residual operation without mutable access to live parent state.
/// Invariants that depend on live state (e.g., the parent's cursor
/// remaining in-bounds after the range shrinks) are validated by
/// backend execution code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResidualPlan<'a> {
    parent_new_spec: ShardSpecRef<'a>,
    residual_spec: ShardSpecRef<'a>,
}

/// Indicates identical parent and residual specifications during residual planning.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SplitResidualPlanError {
    /// `parent_new_spec` and `residual_spec` are identical — a residual
    /// split must shrink the parent and produce a distinct range.
    #[error("split-residual requires parent_new_spec and residual_spec to differ")]
    IdenticalSpecs,
}

impl<'a> SplitResidualPlan<'a> {
    /// Validates structural distinction between parent and residual specifications.
    ///
    /// The only check performed here is that the two specs differ
    /// (identical specs would mean no actual split occurred). The full
    /// coverage contract — `parent_new_spec ∪ residual_spec` equals the
    /// original parent range with no overlap — is enforced by the
    /// coordinator at execution time via [`validate_residual_split`].
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

    /// Returns the retained subset of the parent's key range.
    #[inline]
    #[must_use]
    pub fn parent_new_spec(&self) -> ShardSpecRef<'a> {
        self.parent_new_spec
    }

    /// Returns the offloaded tail section of the key range.
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
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.parent_new_spec.write_canonical(h);
        self.residual_spec.write_canonical(h);
    }
}

/// Failures occurring during split-residual derivation.
///
/// Variants are ordered from most specific (cursor-derived) to most
/// general (downstream coverage validation). The first three variants
/// are exclusive to [`plan_split_residual_from_cursor`]; the last two
/// can arise from any residual planning path.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SplitResidualPlanningError {
    /// Cursor-derived planning requires `cursor.last_key` to be present.
    /// A cursor with no `last_key` has not yet made forward progress, so
    /// there is no meaningful point at which to split.
    #[error("split-residual cursor planning requires cursor.last_key")]
    MissingCursor,
    /// `cursor.last_key` has no representable successor within the
    /// keyspace. This occurs when the key is all-`0xFF` at `MAX_KEY_SIZE`
    /// (the absolute maximum of the byte-ordered keyspace) or when the
    /// key exceeds `MAX_KEY_SIZE`.
    #[error("cursor key has no representable successor")]
    NoSuccessor,
    /// Cursor-derived split point falls outside the parent range.
    #[error("cursor successor falls outside parent range")]
    SplitPointOutOfBounds,
    /// Residual plan shape invariants failed.
    #[error("{0}")]
    InvalidPlan(#[source] SplitResidualPlanError),
    /// Residual partition validation failed against the parent range.
    #[error("{0}")]
    InvalidCoverage(#[source] SplitValidationError),
}

/// Derives a split-residual plan, enforcing strict partition coverage against the parent shard.
///
/// # Errors
///
/// - [`SplitResidualPlanningError::InvalidPlan`] when the candidate specs are
///   structurally invalid.
/// - [`SplitResidualPlanningError::InvalidCoverage`] when the specs do not
///   form a valid residual partition of `parent`.
pub fn plan_split_residual<'a>(
    parent: ShardSpecRef<'a>,
    parent_new_spec: ShardSpecRef<'a>,
    residual_spec: ShardSpecRef<'a>,
) -> Result<SplitResidualPlan<'a>, SplitResidualPlanningError> {
    let plan = SplitResidualPlan::try_new(parent_new_spec, residual_spec)
        .map_err(SplitResidualPlanningError::InvalidPlan)?;
    validate_residual_split(parent, plan.parent_new_spec(), plan.residual_spec())
        .map_err(SplitResidualPlanningError::InvalidCoverage)?;
    Ok(plan)
}

/// Derives a split-residual plan, bisecting the parent range at the specified boundary.
///
/// The split point defines:
/// - parent new range: `[parent.start, split_point)`
/// - residual range: `[split_point, parent.end)`
///
/// # Errors
///
/// Propagates [`SplitResidualPlanningError`] from [`plan_split_residual`].
pub fn plan_split_residual_at_point<'a>(
    parent: ShardSpecRef<'a>,
    split_point: &'a [u8],
) -> Result<SplitResidualPlan<'a>, SplitResidualPlanningError> {
    let parent_new_spec =
        ShardSpecRef::new(parent.key_range_start(), split_point, parent.metadata());
    let residual_spec = ShardSpecRef::new(split_point, parent.key_range_end(), parent.metadata());
    plan_split_residual(parent, parent_new_spec, residual_spec)
}

/// Derives a split-residual plan by offloading keys subsequent to the active cursor.
///
/// Derives the split point as `key_successor(cursor.last_key)` -- the
/// smallest byte string strictly greater than the last processed key --
/// then splits the parent range at that point:
///
/// ```text
///   parent:  [start ──── last_key ──── end)
///                         │
///                   key_successor
///                         │
///                         v
///   new parent: [start, successor)   residual: [successor, end)
/// ```
///
/// This ensures the parent keeps exactly the range it has already
/// scanned through (plus the just-processed key), and the residual gets
/// everything the worker has not yet touched.
///
/// ## Scratch Buffer
///
/// `successor_scratch` is a caller-owned `[u8; MAX_KEY_SIZE]` buffer used
/// to materialize the derived split point. The returned plan borrows from
/// this buffer, so the plan's lifetime is tied to the scratch's lifetime.
/// This avoids heap allocation on the cursor-aware split path.
///
/// # Errors
///
/// - [`SplitResidualPlanningError::MissingCursor`] when `cursor.last_key()` is
///   absent.
/// - [`SplitResidualPlanningError::NoSuccessor`] when the key has no
///   representable successor (all-`0xFF` at `MAX_KEY_SIZE`).
/// - [`SplitResidualPlanningError::SplitPointOutOfBounds`] when the successor
///   falls outside the open interval `(parent.start, parent.end)`.
/// - Any coverage validation error from [`plan_split_residual_at_point`].
pub fn plan_split_residual_from_cursor<'a>(
    parent: ShardSpecRef<'a>,
    cursor: CursorUpdate<'a>,
    successor_scratch: &'a mut [u8; MAX_KEY_SIZE],
) -> Result<SplitResidualPlan<'a>, SplitResidualPlanningError> {
    let last_key = cursor
        .last_key()
        .ok_or(SplitResidualPlanningError::MissingCursor)?;
    let split_point = key_successor_into(last_key, successor_scratch)
        .ok_or(SplitResidualPlanningError::NoSuccessor)?;

    // The split point must lie strictly inside the parent range. If it equals
    // start, the parent's new range would be empty; if it equals or exceeds
    // end, the residual's range would be empty. Either produces a degenerate
    // zero-width shard, which is invalid.
    //
    // An empty key_range_end represents an unbounded upper range (+∞), so any
    // split point is below the upper bound in that case.
    let above_end = !parent.is_end_unbounded() && split_point >= parent.key_range_end();
    if split_point <= parent.key_range_start() || above_end {
        return Err(SplitResidualPlanningError::SplitPointOutOfBounds);
    }

    plan_split_residual_at_point(parent, split_point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::shard_spec::ShardSpec;
    use crate::test_util::{arb_residual_split, arb_valid_n_way_split, canonical_digest};
    use proptest::prelude::*;
    use rstest::rstest;

    #[rstest]
    #[case::zero(0, Err(SplitReplacePlanError::TooFewChildren { count: 0 }))]
    #[case::one(1, Err(SplitReplacePlanError::TooFewChildren { count: 1 }))]
    #[case::two(2, Ok(()))]
    #[case::max(MAX_SPLIT_CHILDREN, Ok(()))]
    #[case::max_plus_one(
        MAX_SPLIT_CHILDREN + 1,
        Err(SplitReplacePlanError::TooManyChildren { count: MAX_SPLIT_CHILDREN + 1 }),
    )]
    fn split_replace_plan_boundary_validation(
        #[case] count: usize,
        #[case] expected: Result<(), SplitReplacePlanError>,
    ) {
        let specs: Vec<_> = (0..count)
            .map(|i| {
                let start = (i as u16).to_be_bytes().to_vec();
                let end = ((i + 1) as u16).to_be_bytes().to_vec();
                ShardSpec::with_range(start, end)
            })
            .collect();
        let cursors: Vec<_> = (0..count).map(|_| CursorUpdate::initial()).collect();
        let children: Vec<SplitReplaceChild> = (0..count)
            .map(|i| SplitReplaceChild::new(specs[i].as_ref(), cursors[i]))
            .collect();
        let result = SplitReplacePlan::try_new(children);
        match expected {
            Ok(()) => assert!(result.is_ok(), "count={count} should be accepted"),
            Err(ref e) => assert_eq!(&result.unwrap_err(), e, "count={count}"),
        }
    }

    #[rstest]
    #[case::zero(
        0,
        Err(SplitReplacePlanningError::InvalidChildCount(
            SplitReplacePlanError::TooFewChildren { count: 0 },
        )),
    )]
    #[case::one(
        1,
        Err(SplitReplacePlanningError::InvalidChildCount(
            SplitReplacePlanError::TooFewChildren { count: 1 },
        )),
    )]
    #[case::two(2, Ok(()))]
    #[case::max(MAX_SPLIT_CHILDREN, Ok(()))]
    #[case::max_plus_one(
        MAX_SPLIT_CHILDREN + 1,
        Err(SplitReplacePlanningError::InvalidChildCount(
            SplitReplacePlanError::TooManyChildren { count: MAX_SPLIT_CHILDREN + 1 },
        )),
    )]
    fn plan_split_replace_boundary_validation(
        #[case] count: usize,
        #[case] expected: Result<(), SplitReplacePlanningError>,
    ) {
        let parent = if count == 0 {
            ShardSpec::with_range([0, 0], [0, 1])
        } else {
            ShardSpec::with_range([0, 0], (count as u16).to_be_bytes())
        };
        let boundaries: Vec<[u8; 2]> = (0..=count).map(|i| (i as u16).to_be_bytes()).collect();
        let children: Vec<_> = (0..count)
            .map(|i| {
                let spec = ShardSpecRef::with_range(&boundaries[i], &boundaries[i + 1]);
                SplitReplaceChild::new(spec, CursorUpdate::initial())
            })
            .collect();

        let result = plan_split_replace(parent.as_ref(), children);
        match expected {
            Ok(()) => assert!(result.is_ok(), "count={count} should be accepted"),
            Err(ref e) => assert_eq!(&result.unwrap_err(), e, "count={count}"),
        }
    }

    #[test]
    fn plan_split_replace_at_points_rejects_over_fanout_before_materialization() {
        let max_plus_one = MAX_SPLIT_CHILDREN + 1;
        let parent = ShardSpec::with_range([0, 0], (max_plus_one as u16).to_be_bytes());
        let split_points: Vec<[u8; 2]> = (1..=MAX_SPLIT_CHILDREN)
            .map(|i| (i as u16).to_be_bytes())
            .collect();
        let mut cursor_calls = 0usize;
        let result = plan_split_replace_at_points(
            parent.as_ref(),
            split_points.iter().map(<[u8; 2]>::as_slice),
            |_, _| {
                cursor_calls += 1;
                CursorUpdate::initial()
            },
        );

        assert_eq!(
            result,
            Err(SplitReplacePlanningError::InvalidChildCount(
                SplitReplacePlanError::TooManyChildren {
                    count: MAX_SPLIT_CHILDREN + 1,
                }
            ))
        );
        assert_eq!(cursor_calls, 0, "children should not be materialized");
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn split_replace_at_points_coverage_and_determinism(
            (parent, children) in arb_valid_n_way_split(),
            meta in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            // Re-create parent with metadata so propagation can be checked.
            let parent = ShardSpec::with_range_and_metadata(
                parent.key_range_start(),
                parent.key_range_end(),
                &meta,
            );

            // Extract internal boundaries from the generated children.
            let split_points: Vec<&[u8]> = children
                .iter()
                .skip(1)
                .map(|c| c.key_range_start())
                .collect();

            let plan_a = plan_split_replace_at_points_initial_cursor(
                parent.as_ref(),
                split_points.iter().copied(),
            ).unwrap();
            let plan_b = plan_split_replace_at_points_initial_cursor(
                parent.as_ref(),
                split_points.iter().copied(),
            ).unwrap();

            // Child count matches the partition.
            prop_assert_eq!(plan_a.children().len(), children.len());

            // Each child's range matches the generated partition.
            for (actual, expected) in plan_a.children().iter().zip(&children) {
                prop_assert_eq!(
                    actual.spec().key_range_start(),
                    expected.key_range_start(),
                );
                prop_assert_eq!(
                    actual.spec().key_range_end(),
                    expected.key_range_end(),
                );
                // Metadata propagated to every child.
                prop_assert_eq!(actual.spec().metadata(), meta.as_slice());
            }

            // Deterministic: same inputs produce the same canonical digest.
            prop_assert_eq!(canonical_digest(&plan_a), canonical_digest(&plan_b));
        }

        #[test]
        fn split_residual_at_point_coverage_and_determinism(
            base in proptest::collection::vec(any::<u8>(), 1..16),
            suffix1 in proptest::collection::vec(any::<u8>(), 1..8),
            suffix2 in proptest::collection::vec(any::<u8>(), 1..8),
            meta in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            // Build (start, mid, end) via suffix accumulation: start < mid < end.
            let start = base.clone();
            let mut mid = base.clone();
            mid.extend_from_slice(&suffix1);
            let mut end = mid.clone();
            end.extend_from_slice(&suffix2);

            let parent = ShardSpec::with_range_and_metadata(&start, &end, &meta);
            let plan_a = plan_split_residual_at_point(parent.as_ref(), &mid).unwrap();
            let plan_b = plan_split_residual_at_point(parent.as_ref(), &mid).unwrap();

            // Parent_new covers [start, mid).
            prop_assert_eq!(plan_a.parent_new_spec().key_range_start(), start.as_slice());
            prop_assert_eq!(plan_a.parent_new_spec().key_range_end(), mid.as_slice());
            // Residual covers [mid, end).
            prop_assert_eq!(plan_a.residual_spec().key_range_start(), mid.as_slice());
            prop_assert_eq!(plan_a.residual_spec().key_range_end(), end.as_slice());
            // Metadata propagated to both halves.
            prop_assert_eq!(plan_a.parent_new_spec().metadata(), meta.as_slice());
            prop_assert_eq!(plan_a.residual_spec().metadata(), meta.as_slice());
            // Deterministic: same inputs produce the same canonical digest.
            prop_assert_eq!(canonical_digest(&plan_a), canonical_digest(&plan_b));
        }

        #[test]
        fn split_residual_strategy_coverage(
            (parent, split_point) in arb_residual_split(),
            meta in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let parent = ShardSpec::with_range_and_metadata(
                parent.key_range_start(),
                parent.key_range_end(),
                &meta,
            );
            let plan = plan_split_residual_at_point(parent.as_ref(), &split_point).unwrap();

            // Parent_new covers [start, split_point).
            prop_assert_eq!(plan.parent_new_spec().key_range_start(), parent.key_range_start());
            prop_assert_eq!(plan.parent_new_spec().key_range_end(), split_point.as_slice());
            // Residual covers [split_point, end).
            prop_assert_eq!(plan.residual_spec().key_range_start(), split_point.as_slice());
            prop_assert_eq!(plan.residual_spec().key_range_end(), parent.key_range_end());
            // Metadata propagated.
            prop_assert_eq!(plan.parent_new_spec().metadata(), meta.as_slice());
            prop_assert_eq!(plan.residual_spec().metadata(), meta.as_slice());
        }
    }

    #[test]
    fn split_replace_at_points_empty_rejected() {
        let parent = ShardSpec::with_range(b"a", b"z");
        let split_points: &[&[u8]] = &[];

        let err = plan_split_replace_at_points_initial_cursor(
            parent.as_ref(),
            split_points.iter().copied(),
        )
        .unwrap_err();

        assert_eq!(
            err,
            SplitReplacePlanningError::InvalidChildCount(SplitReplacePlanError::TooFewChildren {
                count: 1
            },),
        );
    }

    #[test]
    fn plan_split_replace_at_points_rejects_out_of_order() {
        let parent = ShardSpec::with_range(b"a", b"z");
        let result = plan_split_replace_at_points_initial_cursor(
            parent.as_ref(),
            [b"m".as_slice(), b"f".as_slice()],
        );
        assert!(
            matches!(result, Err(SplitReplacePlanningError::InvalidCoverage(_))),
            "expected InvalidCoverage for out-of-order points, got {result:?}",
        );
    }

    #[test]
    fn plan_split_replace_at_points_accepts_max_children() {
        let max_points = MAX_SPLIT_CHILDREN - 1;
        let parent = ShardSpec::with_range(
            [0u8, 0].as_slice(),
            (MAX_SPLIT_CHILDREN as u16).to_be_bytes().as_slice(),
        );
        let points: Vec<[u8; 2]> = (1..=max_points).map(|i| (i as u16).to_be_bytes()).collect();
        let plan = plan_split_replace_at_points_initial_cursor(
            parent.as_ref(),
            points.iter().map(|p| p.as_slice()),
        );
        assert!(
            plan.is_ok(),
            "MAX_SPLIT_CHILDREN children should be accepted"
        );
        assert_eq!(plan.unwrap().children().len(), MAX_SPLIT_CHILDREN);
    }

    #[test]
    fn split_replace_invalid_coverage_gap_rejected() {
        let parent = ShardSpec::with_range(b"a", b"z");
        let child_a_spec = ShardSpec::with_range(b"a", b"m");
        let child_b_spec = ShardSpec::with_range(b"n", b"z");
        let cursor = CursorUpdate::initial();

        let children = [
            SplitReplaceChild::new(child_a_spec.as_ref(), cursor),
            SplitReplaceChild::new(child_b_spec.as_ref(), cursor),
        ];

        let err = plan_split_replace(parent.as_ref(), children).unwrap_err();
        assert!(
            matches!(err, SplitReplacePlanningError::InvalidCoverage(_)),
            "expected InvalidCoverage, got {err:?}",
        );
    }

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

    #[test]
    fn plan_split_residual_accepts_valid_partition() {
        let parent = ShardSpec::with_range_and_metadata(b"a", b"z", b"meta");
        let new_parent = ShardSpecRef::new(b"a", b"m", b"meta");
        let residual = ShardSpecRef::new(b"m", b"z", b"meta");
        let plan = plan_split_residual(parent.as_ref(), new_parent, residual).unwrap();
        assert_eq!(plan.parent_new_spec().key_range_start(), b"a");
        assert_eq!(plan.parent_new_spec().key_range_end(), b"m");
        assert_eq!(plan.residual_spec().key_range_start(), b"m");
        assert_eq!(plan.residual_spec().key_range_end(), b"z");
        assert_eq!(plan.parent_new_spec().metadata(), b"meta");
        assert_eq!(plan.residual_spec().metadata(), b"meta");
    }

    #[test]
    fn plan_split_residual_rejects_coverage_violation() {
        let parent = ShardSpec::with_range(b"a", b"z");
        let new_parent = ShardSpecRef::new(b"a", b"m", b"");
        let residual = ShardSpecRef::new(b"n", b"z", b"");
        let err = plan_split_residual(parent.as_ref(), new_parent, residual).unwrap_err();
        assert!(
            matches!(err, SplitResidualPlanningError::InvalidCoverage(_)),
            "expected InvalidCoverage, got {err:?}",
        );
    }

    #[test]
    fn plan_split_residual_from_cursor_uses_successor_split_point() {
        let parent = ShardSpec::with_range_and_metadata(b"a", b"z", b"meta");
        let cursor = CursorUpdate::with_last_key(b"m");
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let plan = plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch).unwrap();

        assert_eq!(plan.parent_new_spec().key_range_start(), b"a");
        assert_eq!(plan.parent_new_spec().key_range_end(), b"m\0");
        assert_eq!(plan.residual_spec().key_range_start(), b"m\0");
        assert_eq!(plan.residual_spec().key_range_end(), b"z");
        assert_eq!(plan.parent_new_spec().metadata(), b"meta");
        assert_eq!(plan.residual_spec().metadata(), b"meta");
    }

    #[rstest]
    #[case::missing_cursor(
        b"a".as_slice(),
        b"z".as_slice(),
        None,
        SplitResidualPlanningError::MissingCursor,
    )]
    #[case::no_successor(
        &[0u8],
        &[u8::MAX; MAX_KEY_SIZE],
        Some([u8::MAX; MAX_KEY_SIZE].as_slice()),
        SplitResidualPlanningError::NoSuccessor,
    )]
    #[case::successor_on_parent_end(
        b"a".as_slice(),
        b"m\0",
        Some(b"m".as_slice()),
        SplitResidualPlanningError::SplitPointOutOfBounds,
    )]
    #[case::successor_below_parent_start(
        b"m".as_slice(),
        b"z".as_slice(),
        Some(b"a".as_slice()),
        SplitResidualPlanningError::SplitPointOutOfBounds,
    )]
    #[case::cursor_above_parent_end(
        b"a".as_slice(),
        b"m".as_slice(),
        Some(b"z".as_slice()),
        SplitResidualPlanningError::SplitPointOutOfBounds,
    )]
    fn plan_split_residual_from_cursor_rejects(
        #[case] start: &[u8],
        #[case] end: &[u8],
        #[case] last_key: Option<&[u8]>,
        #[case] expected: SplitResidualPlanningError,
    ) {
        let parent = ShardSpec::with_range(start, end);
        let cursor = match last_key {
            Some(k) => CursorUpdate::with_last_key(k),
            None => CursorUpdate::initial(),
        };
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let err =
            plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch).unwrap_err();
        assert_eq!(err, expected);
    }

    #[test]
    fn cursor_split_at_parent_start_boundary() {
        let parent = ShardSpec::with_range(b"a", b"z");
        let cursor = CursorUpdate::with_last_key(b"a");
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let plan = plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch).unwrap();
        // successor of "a" is "a\0", which is strictly inside (a, z)
        assert_eq!(plan.parent_new_spec().key_range_start(), b"a");
        assert_eq!(plan.parent_new_spec().key_range_end(), b"a\0");
        assert_eq!(plan.residual_spec().key_range_start(), b"a\0");
        assert_eq!(plan.residual_spec().key_range_end(), b"z");
    }

    #[test]
    fn cursor_split_accepts_unbounded_tail_parent() {
        // Parent with unbounded upper range: [b"a", +∞).
        // Empty key_range_end represents unbounded.
        let parent = ShardSpec::with_range(b"a".as_slice(), b"".as_slice());
        let cursor = CursorUpdate::with_last_key(b"m");
        let mut scratch = [0u8; MAX_KEY_SIZE];

        // Successor of "m" is "m\0", which lies inside [a, +∞).
        let plan = plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch);
        assert!(
            plan.is_ok(),
            "unbounded-tail parent should accept a valid interior split, got {plan:?}",
        );

        let plan = plan.unwrap();
        assert_eq!(plan.parent_new_spec().key_range_start(), b"a");
        assert_eq!(plan.parent_new_spec().key_range_end(), b"m\0");
        assert_eq!(plan.residual_spec().key_range_start(), b"m\0");
        // Residual inherits the unbounded end.
        assert!(plan.residual_spec().key_range_end().is_empty());
    }

    #[test]
    fn cursor_split_strips_trailing_0xff_at_max_key_size() {
        // Key: [0x01, 0xFF, 0xFF, ...] at MAX_KEY_SIZE.
        // prefix_successor_into strips trailing 0xFF bytes, leaving [0x01],
        // then increments → [0x02].
        let mut key = [0xFF; MAX_KEY_SIZE];
        key[0] = 0x01;
        let parent = ShardSpec::with_range([0x00], [0x03]);
        let cursor = CursorUpdate::with_last_key(&key);
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let plan = plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch).unwrap();

        assert_eq!(plan.parent_new_spec().key_range_start(), &[0x00]);
        assert_eq!(plan.parent_new_spec().key_range_end(), &[0x02]);
        assert_eq!(plan.residual_spec().key_range_start(), &[0x02]);
        assert_eq!(plan.residual_spec().key_range_end(), &[0x03]);
    }

    #[test]
    fn cursor_split_increments_last_byte_at_max_key_size() {
        // Key: all 0x50 at MAX_KEY_SIZE.
        // prefix_successor_into finds the last non-0xFF byte (the last byte,
        // 0x50) and increments it → 0x51. Successor stays at MAX_KEY_SIZE.
        let key = [0x50; MAX_KEY_SIZE];
        let parent = ShardSpec::with_range([0x00], [0xFF]);
        let cursor = CursorUpdate::with_last_key(&key);
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let plan = plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch).unwrap();

        let mut expected_successor = [0x50; MAX_KEY_SIZE];
        expected_successor[MAX_KEY_SIZE - 1] = 0x51;
        assert_eq!(plan.parent_new_spec().key_range_start(), &[0x00]);
        assert_eq!(plan.parent_new_spec().key_range_end(), &expected_successor);
        assert_eq!(plan.residual_spec().key_range_start(), &expected_successor);
        assert_eq!(plan.residual_spec().key_range_end(), &[0xFF]);
    }

    // -- Direct tests for plan_split_residual_at_point ------------------------

    #[test]
    fn plan_split_residual_at_point_happy_path() {
        let parent = ShardSpec::with_range_and_metadata(b"a", b"z", b"meta");
        let plan = plan_split_residual_at_point(parent.as_ref(), b"m").unwrap();

        assert_eq!(plan.parent_new_spec().key_range_start(), b"a");
        assert_eq!(plan.parent_new_spec().key_range_end(), b"m");
        assert_eq!(plan.residual_spec().key_range_start(), b"m");
        assert_eq!(plan.residual_spec().key_range_end(), b"z");
        assert_eq!(plan.parent_new_spec().metadata(), b"meta");
        assert_eq!(plan.residual_spec().metadata(), b"meta");
    }

    #[test]
    fn plan_split_residual_at_point_rejects_split_before_range() {
        // Split point before parent start reorders sorted children,
        // causing a StartMismatch in coverage validation.
        let parent = ShardSpec::with_range(b"c", b"m");
        let err = plan_split_residual_at_point(parent.as_ref(), b"a").unwrap_err();
        assert!(
            matches!(err, SplitResidualPlanningError::InvalidCoverage(_)),
            "split before parent range should be rejected, got {err:?}",
        );
    }

    #[test]
    fn plan_split_residual_at_point_rejects_identical_specs() {
        // Degenerate parent where start == end: splitting at the shared
        // boundary produces identical parent_new and residual specs.
        // Uses ShardSpecRef::new (no validation) to bypass the owned-type
        // panic on start >= end.
        let parent = ShardSpecRef::new(b"m", b"m", b"");
        let err = plan_split_residual_at_point(parent, b"m").unwrap_err();
        assert_eq!(
            err,
            SplitResidualPlanningError::InvalidPlan(SplitResidualPlanError::IdenticalSpecs),
        );
    }

    #[rstest]
    #[case::split_at_parent_start(b"m", b"z", b"m", true)]
    #[case::split_at_parent_end(b"a", b"m", b"m", true)]
    #[case::split_beyond_parent_end(b"a", b"m", b"z", true)]
    #[case::valid_interior(b"a", b"z", b"m", false)]
    fn plan_split_residual_at_point_edge_cases(
        #[case] start: &[u8],
        #[case] end: &[u8],
        #[case] split_point: &[u8],
        #[case] should_err: bool,
    ) {
        let parent = ShardSpec::with_range(start, end);
        let result = plan_split_residual_at_point(parent.as_ref(), split_point);
        if should_err {
            assert!(
                result.is_err(),
                "expected error for split_point={split_point:?} in [{start:?}, {end:?})"
            );
        } else {
            assert!(
                result.is_ok(),
                "expected success for split_point={split_point:?} in [{start:?}, {end:?})"
            );
        }
    }
}
