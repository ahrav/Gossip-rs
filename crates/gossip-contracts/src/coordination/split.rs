//! Split planning types and helper constructors.
//!
//! Ownership boundary:
//! - This module owns backend-agnostic split planning:
//!   - split-replace child-count shape checks and parent-range coverage validation
//!   - split-residual partition planning and cursor-successor split-point derivation
//! - Execution-time concerns stay in `gossip-coordination` backends:
//!   lease/fence checks, spawn-limit checks, derived-ID collision handling,
//!   idempotency/op-log behavior, and record mutation ordering.
//!
//! The planner operates on borrowed [`ShardSpecRef`] / [`CursorUpdate`] views,
//! so callers can construct plans without committing to a specific storage
//! backend.

use std::fmt;

use crate::coordination::cursor::{CursorUpdate, MAX_KEY_SIZE};
use crate::coordination::limits::MAX_SPLIT_CHILDREN;
use crate::coordination::shard_spec::{
    ShardSpecRef, SplitValidationError, validate_residual_split, validate_split_coverage_bounds,
};
use crate::identity::CanonicalBytes;
use blake3::Hasher;
use gossip_stdx::InlineVec;

/// A single child in a [`SplitReplacePlan`].
///
/// Each child carries its [`ShardSpecRef`] (the key sub-range it covers)
/// and an initial [`CursorUpdate`] (where scanning should begin).
///
/// The planner carries cursor payloads through unchanged. It does not
/// validate cursor semantics against live shard state.
///
/// `split_replace` execution treats child cursors as opaque plan payload.
/// Execution validates shape/coverage but does not re-check cursor bounds
/// against child specs, so callers must construct child cursors intentionally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitReplaceChild<'a> {
    spec: ShardSpecRef<'a>,
    cursor: CursorUpdate<'a>,
}

impl<'a> SplitReplaceChild<'a> {
    /// Construct a new child entry from a key sub-range and initial cursor.
    #[must_use]
    pub fn new(spec: ShardSpecRef<'a>, cursor: CursorUpdate<'a>) -> Self {
        Self { spec, cursor }
    }

    /// The child's shard specification (key sub-range).
    #[inline]
    #[must_use]
    pub fn spec(&self) -> ShardSpecRef<'a> {
        self.spec
    }

    /// The child's initial cursor position.
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

/// Plan for a split-replace operation: parent is replaced by >= 2 children
/// that collectively cover the parent's key range.
///
/// Child order is preserved exactly as supplied by the caller. Coverage checks
/// sort internally by `key_range_start`, but canonical encoding/hashing keeps
/// caller order. Callers that need order-stable payload hashes across retries
/// should supply deterministic ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplacePlan<'a> {
    children: InlineVec<SplitReplaceChild<'a>, MAX_SPLIT_CHILDREN>,
}

/// Error returned when a [`SplitReplacePlan`] is constructed with an
/// invalid number of children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitReplacePlanError {
    /// Fewer than 2 children — not a split.
    TooFewChildren { count: usize },
    /// More than [`MAX_SPLIT_CHILDREN`] children.
    ///
    /// `count` is a lower bound: the iterator is not fully consumed once
    /// the limit is exceeded, so the actual count may be higher.
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

impl<'a> SplitReplacePlan<'a> {
    /// Construct a validated split-replace plan.
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

    /// The children in this plan, in caller-provided order.
    #[inline]
    #[must_use]
    pub fn children(&self) -> &[SplitReplaceChild<'a>] {
        self.children.as_slice()
    }
}

const _: () = assert!(MAX_SPLIT_CHILDREN <= u32::MAX as usize);

impl CanonicalBytes for SplitReplacePlan<'_> {
    fn write_canonical(&self, h: &mut Hasher) {
        u32::try_from(self.children.len())
            .expect("child count exceeds u32")
            .write_canonical(h);
        for child in &self.children {
            child.write_canonical(h);
        }
    }
}

/// Error returned by split-replace planning free functions.
///
/// Distinguishes shape errors (invalid child count) from semantic errors
/// (children do not form a valid partition of the parent range).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitReplacePlanningError {
    /// Plan child-count invariants failed (`< 2` or `> MAX_SPLIT_CHILDREN`).
    InvalidChildCount(SplitReplacePlanError),
    /// Child ranges failed split coverage validation against the parent.
    InvalidCoverage(SplitValidationError),
}

impl fmt::Display for SplitReplacePlanningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChildCount(err) => err.fmt(f),
            Self::InvalidCoverage(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for SplitReplacePlanningError {}

/// Build and validate a split-replace plan against a parent shard.
///
/// This helper enforces both child-count bounds and full coverage
/// correctness via [`validate_split_coverage_bounds`].
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

/// Build a split-replace plan from explicit split points.
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

/// Build a split-replace plan from explicit split points using
/// [`CursorUpdate::initial`] for all children.
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

// ============================================================================
// Split-residual planning
// ============================================================================

/// Plan for a split-residual operation: parent shrinks its key range and
/// a new residual shard covers the remainder.
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
    /// split must shrink the parent and produce a distinct range.
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

    /// The parent's new (shrunk) specification.
    #[inline]
    #[must_use]
    pub fn parent_new_spec(&self) -> ShardSpecRef<'a> {
        self.parent_new_spec
    }

    /// The residual shard's specification.
    #[inline]
    #[must_use]
    pub fn residual_spec(&self) -> ShardSpecRef<'a> {
        self.residual_spec
    }
}

impl CanonicalBytes for SplitResidualPlan<'_> {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.parent_new_spec.write_canonical(h);
        self.residual_spec.write_canonical(h);
    }
}

/// Error returned by split-residual planning helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitResidualPlanningError {
    /// Cursor-derived planning requires `cursor.last_key`.
    MissingCursor,
    /// `cursor.last_key` has no representable successor within the keyspace.
    NoSuccessor,
    /// Cursor-derived split point falls outside the parent range.
    ///
    /// Fields store byte lengths rather than raw key bytes to avoid logging
    /// potentially large cursor payloads.
    SplitPointOutOfBounds {
        /// Length of the derived split point (`key_successor(cursor.last_key)`).
        split_point: usize,
        /// Length of `parent.key_range_start()`.
        parent_start: usize,
        /// Length of `parent.key_range_end()`.
        parent_end: usize,
    },
    /// Residual plan shape invariants failed.
    InvalidPlan(SplitResidualPlanError),
    /// Residual partition validation failed against the parent range.
    InvalidCoverage(SplitValidationError),
}

impl fmt::Display for SplitResidualPlanningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCursor => {
                write!(f, "split-residual cursor planning requires cursor.last_key")
            }
            Self::NoSuccessor => write!(f, "cursor key has no representable successor"),
            Self::SplitPointOutOfBounds { .. } => {
                write!(f, "cursor successor falls outside parent range")
            }
            Self::InvalidPlan(err) => err.fmt(f),
            Self::InvalidCoverage(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for SplitResidualPlanningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPlan(err) => Some(err),
            Self::InvalidCoverage(err) => Some(err),
            _ => None,
        }
    }
}

/// Build and validate a split-residual plan against a parent shard.
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

/// Build a split-residual plan from an explicit split point.
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

#[inline]
fn prefix_successor_into<'a>(prefix: &[u8], out: &'a mut [u8; MAX_KEY_SIZE]) -> Option<&'a [u8]> {
    if prefix.is_empty() || prefix.len() > MAX_KEY_SIZE {
        return None;
    }
    let last_non_ff = prefix.iter().rposition(|&byte| byte != u8::MAX)?;
    let out_len = last_non_ff + 1;
    out[..out_len].copy_from_slice(&prefix[..out_len]);
    out[last_non_ff] += 1;
    Some(&out[..out_len])
}

#[inline]
fn key_successor_into<'a>(key: &[u8], out: &'a mut [u8; MAX_KEY_SIZE]) -> Option<&'a [u8]> {
    if key.len() > MAX_KEY_SIZE {
        return None;
    }

    if key.len() < MAX_KEY_SIZE {
        out[..key.len()].copy_from_slice(key);
        out[key.len()] = 0;
        return Some(&out[..key.len() + 1]);
    }

    prefix_successor_into(key, out)
}

/// Build a split-residual plan from a cursor, using successor semantics.
///
/// The split point is derived as `key_successor(cursor.last_key)` and the plan
/// is then built as `[parent.start, split_point)` + `[split_point, parent.end)`.
///
/// `successor_scratch` is caller-owned reusable storage for the derived split
/// point and allows the returned plan to remain fully borrowed.
///
/// # Errors
///
/// - [`SplitResidualPlanningError::MissingCursor`] when `cursor.last_key()` is
///   absent.
/// - [`SplitResidualPlanningError::NoSuccessor`] when the key has no
///   representable successor.
/// - [`SplitResidualPlanningError::SplitPointOutOfBounds`] when the successor
///   is outside `(parent.start, parent.end)`.
/// - Any validation error from [`plan_split_residual_at_point`].
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

    if split_point <= parent.key_range_start() || split_point >= parent.key_range_end() {
        return Err(SplitResidualPlanningError::SplitPointOutOfBounds {
            split_point: split_point.len(),
            parent_start: parent.key_range_start().len(),
            parent_end: parent.key_range_end().len(),
        });
    }

    plan_split_residual_at_point(parent, split_point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::shard_spec::ShardSpec;
    use crate::test_util::canonical_digest;

    #[test]
    fn split_replace_plan_boundary_validation() {
        let cases: &[(usize, Result<(), SplitReplacePlanError>)] = &[
            (0, Err(SplitReplacePlanError::TooFewChildren { count: 0 })),
            (1, Err(SplitReplacePlanError::TooFewChildren { count: 1 })),
            (2, Ok(())),
            (MAX_SPLIT_CHILDREN, Ok(())),
            (
                MAX_SPLIT_CHILDREN + 1,
                Err(SplitReplacePlanError::TooManyChildren {
                    count: MAX_SPLIT_CHILDREN + 1,
                }),
            ),
        ];

        for &(count, ref expected) in cases {
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
                Err(e) => assert_eq!(&result.unwrap_err(), e, "count={count}"),
            }
        }
    }

    /// Boundary validation for `plan_split_replace` over child-count edges:
    /// 0, 1, 2, MAX, MAX+1.
    #[test]
    fn plan_split_replace_boundary_validation() {
        let cases: &[(usize, Result<(), SplitReplacePlanningError>)] = &[
            (
                0,
                Err(SplitReplacePlanningError::InvalidChildCount(
                    SplitReplacePlanError::TooFewChildren { count: 0 },
                )),
            ),
            (
                1,
                Err(SplitReplacePlanningError::InvalidChildCount(
                    SplitReplacePlanError::TooFewChildren { count: 1 },
                )),
            ),
            (2, Ok(())),
            (MAX_SPLIT_CHILDREN, Ok(())),
            (
                MAX_SPLIT_CHILDREN + 1,
                Err(SplitReplacePlanningError::InvalidChildCount(
                    SplitReplacePlanError::TooManyChildren {
                        count: MAX_SPLIT_CHILDREN + 1,
                    },
                )),
            ),
        ];

        for &(count, ref expected) in cases {
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
                Err(e) => assert_eq!(&result.unwrap_err(), e, "count={count}"),
            }
        }
    }

    /// `plan_split_replace_at_points` must reject `MAX+1` children before
    /// constructing any child specs/cursors.
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

    #[test]
    fn split_replace_planner_points_produces_coverage_valid_deterministic_plan() {
        let parent = ShardSpec::with_range_and_metadata(b"a", b"z", b"meta");
        let split_points = [b"m".as_slice()];

        let plan_a =
            plan_split_replace_at_points_initial_cursor(parent.as_ref(), split_points).unwrap();
        let plan_b =
            plan_split_replace_at_points_initial_cursor(parent.as_ref(), split_points).unwrap();

        assert_eq!(plan_a.children().len(), 2);
        assert_eq!(plan_a.children()[0].spec().key_range_start(), b"a");
        assert_eq!(plan_a.children()[0].spec().key_range_end(), b"m");
        assert_eq!(plan_a.children()[1].spec().key_range_start(), b"m");
        assert_eq!(plan_a.children()[1].spec().key_range_end(), b"z");
        assert_eq!(plan_a.children()[0].spec().metadata(), b"meta");
        assert_eq!(plan_a.children()[1].spec().metadata(), b"meta");
        assert_eq!(canonical_digest(&plan_a), canonical_digest(&plan_b));
    }

    #[test]
    fn split_replace_at_points_three_children() {
        let parent = ShardSpec::with_range_and_metadata(b"a", b"z", b"meta");
        let split_points: &[&[u8]] = &[b"g", b"m"];

        let plan = plan_split_replace_at_points_initial_cursor(
            parent.as_ref(),
            split_points.iter().copied(),
        )
        .unwrap();

        assert_eq!(plan.children().len(), 3);
        assert_eq!(plan.children()[0].spec().key_range_start(), b"a");
        assert_eq!(plan.children()[0].spec().key_range_end(), b"g");
        assert_eq!(plan.children()[1].spec().key_range_start(), b"g");
        assert_eq!(plan.children()[1].spec().key_range_end(), b"m");
        assert_eq!(plan.children()[2].spec().key_range_start(), b"m");
        assert_eq!(plan.children()[2].spec().key_range_end(), b"z");
        for child in plan.children() {
            assert_eq!(child.spec().metadata(), b"meta");
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

    #[test]
    fn plan_split_residual_from_cursor_rejects_missing_cursor() {
        let parent = ShardSpec::with_range(b"a", b"z");
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let err =
            plan_split_residual_from_cursor(parent.as_ref(), CursorUpdate::initial(), &mut scratch)
                .unwrap_err();
        assert_eq!(err, SplitResidualPlanningError::MissingCursor);
    }

    #[test]
    fn plan_split_residual_from_cursor_rejects_no_successor() {
        let end = vec![u8::MAX; MAX_KEY_SIZE];
        let parent = ShardSpec::with_range([0u8], end.as_slice());
        let cursor = CursorUpdate::with_last_key(end.as_slice());
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let err =
            plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch).unwrap_err();
        assert_eq!(err, SplitResidualPlanningError::NoSuccessor);
    }

    #[test]
    fn plan_split_residual_from_cursor_rejects_successor_on_parent_end() {
        let parent = ShardSpec::with_range(b"a", b"m\0");
        let cursor = CursorUpdate::with_last_key(b"m");
        let mut scratch = [0u8; MAX_KEY_SIZE];
        let err =
            plan_split_residual_from_cursor(parent.as_ref(), cursor, &mut scratch).unwrap_err();
        assert_eq!(
            err,
            SplitResidualPlanningError::SplitPointOutOfBounds {
                split_point: 2,
                parent_start: 1,
                parent_end: 2,
            },
        );
    }
}
