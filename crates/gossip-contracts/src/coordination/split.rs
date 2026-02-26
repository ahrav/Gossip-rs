//! Split-replace planning types and helper constructors.
//!
//! Ownership boundary:
//! - This module owns backend-agnostic split-replace planning: child-count
//!   shape checks and parent-range coverage validation.
//! - Execution-time concerns stay in `gossip-coordination` backends:
//!   lease/fence checks, spawn-limit checks, derived-ID collision handling,
//!   idempotency/op-log behavior, and record mutation ordering.
//!
//! The planner operates on borrowed [`ShardSpecRef`] / [`CursorUpdate`] views,
//! so callers can construct plans without committing to a specific storage
//! backend.

use std::fmt;

use crate::coordination::cursor::CursorUpdate;
use crate::coordination::limits::MAX_SPLIT_CHILDREN;
use crate::coordination::shard_spec::{
    ShardSpecRef, SplitValidationError, validate_split_coverage_bounds,
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
/// Today, `split_replace` execution also treats child cursors as opaque plan
/// payload (shape/coverage are validated, cursor bounds are not re-checked), so
/// callers should construct child cursors intentionally.
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
    let mut points: Vec<&'a [u8]> = Vec::new();
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
}
