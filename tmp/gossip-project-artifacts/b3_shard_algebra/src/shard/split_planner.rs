//! Typed split algebra: connector-facing API for constructing
//! `SplitReplacePlan` and `SplitResidualPlan` using typed keys,
//! structured metadata, and automatic hint propagation.
//!
//! ## Design Decisions (locked)
//!
//! D3.15: Split planning is separated from split execution. The planner
//!        produces a B2 plan value; the connector then submits it.
//!        Planning is pure computation (no I/O, no lease needed).
//!
//! D3.16: Hint propagation is automatic. If the parent's hint cannot
//!        be decoded, falls back to `ShardHint::Range` (defensive).
//!
//! D3.17: The planner validates split points before producing a plan
//!        (defense-in-depth; B2 also validates).
//!
//! D3.18: `SplitPlanner` is NOT generic over key type. Split points
//!        are raw `Vec<u8>` or via helper methods that encode typed keys.
//!
//! D3.19: Connector-extra for children is provided via a closure
//!        `Fn(usize, &[u8], &[u8]) -> Vec<u8>`.

use core::fmt;

use crate::coordination::cursor::Cursor;
use crate::coordination::shard_spec::{
    ShardSpec,
    SplitReplaceChild,
    SplitReplacePlan,
    SplitResidualPlan,
    validate_split_coverage,
    validate_residual_split,
};

use super::hint::{
    ShardHint,
    ShardMetadata,
    propagate_hint_on_split,
};
use super::key_encoding::{
    KeyEncoding,
    ManifestRowKey,
    byte_midpoint,
};

// ============================================================================
// § SplitPlanner
// ============================================================================

/// Planner for constructing split operations on an existing shard.
///
/// ## Lifecycle
///
/// ```text
/// 1. Create:   SplitPlanner::for_shard(&parent_spec)
/// 2. Plan:     .split_at(points)  OR  .split_at_midpoint()  OR  .residual_at(point)
/// 3. Submit:   coordinator.split_replace(... plan ...) / split_residual(...)
/// ```
///
/// ## Invariants
///
/// **Safety (hint propagation)**: Every child has a hint derived from
/// the parent via `propagate_hint_on_split`, or Range on failure.
///
/// **Safety (coverage preservation)**: Children tile the parent.
///
/// **Safety (plan purity)**: No I/O, no network, no blocking.
pub struct SplitPlanner {
    /// Parent shard's spec.
    parent_spec: ShardSpec,

    /// Decoded hint from the parent, or Range on decode failure.
    parent_hint: ShardHint,

    /// Parent's connector_extra.
    parent_connector_extra: Box<[u8]>,
}

impl SplitPlanner {
    /// Create a planner for splitting an existing shard.
    ///
    /// Decodes the parent's hint from its metadata. If decoding fails,
    /// falls back to `ShardHint::Range` and empty connector_extra.
    pub fn for_shard(parent_spec: &ShardSpec) -> Self {
        let (parent_hint, parent_connector_extra) =
            match parent_spec.decode_metadata() {
                Ok(meta) => (meta.hint, meta.connector_extra),
                Err(_) => (ShardHint::Range, Box::new([]) as Box<[u8]>),
            };

        Self {
            parent_spec: parent_spec.clone(),
            parent_hint,
            parent_connector_extra,
        }
    }

    /// The parent's key range start.
    #[inline]
    pub fn parent_start(&self) -> &[u8] {
        &self.parent_spec.key_range_start
    }

    /// The parent's key range end.
    #[inline]
    pub fn parent_end(&self) -> &[u8] {
        &self.parent_spec.key_range_end
    }

    /// The parent's decoded hint.
    #[inline]
    pub fn parent_hint(&self) -> &ShardHint {
        &self.parent_hint
    }

    /// The parent's connector extra.
    #[inline]
    pub fn parent_connector_extra(&self) -> &[u8] {
        &self.parent_connector_extra
    }

    // ── SplitReplace planning ──────────────────────────────────────────

    /// Split the parent at one or more explicit byte-encoded split points.
    ///
    /// Produces a `SplitReplacePlan` with `points.len() + 1` children
    /// whose ranges tile the parent: `[start, p0), [p0, p1), ..., [pN, end)`.
    ///
    /// ## Errors
    ///
    /// Returns `SplitPlanError` if points are empty, out of range,
    /// or not in strictly ascending order.
    pub fn split_at(
        &self,
        points: &[Vec<u8>],
        connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
    ) -> Result<SplitReplacePlan, SplitPlanError> {
        if points.is_empty() {
            return Err(SplitPlanError::NoSplitPoints);
        }

        self.validate_split_points(points)?;

        // Build boundary sequence: [start, p0, p1, ..., pN, end].
        let mut boundaries: Vec<&[u8]> =
            Vec::with_capacity(points.len() + 2);
        boundaries.push(&self.parent_spec.key_range_start);
        for p in points {
            boundaries.push(p.as_slice());
        }
        boundaries.push(&self.parent_spec.key_range_end);

        // Construct children.
        let mut children = Vec::with_capacity(boundaries.len() - 1);
        for i in 0..(boundaries.len() - 1) {
            let child_start = boundaries[i];
            let child_end = boundaries[i + 1];

            let child_hint =
                self.propagate_hint_safe(child_start, child_end);
            let extra = connector_extra_fn(i, child_start, child_end);
            let metadata = ShardMetadata::new(child_hint, extra);

            let spec = ShardSpec::with_range_and_metadata(
                child_start.to_vec(),
                child_end.to_vec(),
                metadata.encode(),
            );

            children.push(SplitReplaceChild {
                spec,
                cursor: Cursor::initial(),
            });
        }

        Ok(SplitReplacePlan { children })
    }

    /// Split the parent at a single typed key.
    pub fn split_at_key<K: KeyEncoding>(
        &self,
        key: &K,
        connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
    ) -> Result<SplitReplacePlan, SplitPlanError> {
        let encoded = key.encode();
        self.split_at(&[encoded], connector_extra_fn)
    }

    /// Split the parent at N−1 equally-spaced midpoints, producing N children.
    ///
    /// Uses `byte_midpoint` recursively.
    ///
    /// ## Errors
    ///
    /// Returns `SplitPlanError::NoViableMidpoint` if the range is too
    /// narrow to split at all.
    pub fn split_at_midpoint(
        &self,
        n: usize,
        connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
    ) -> Result<SplitReplacePlan, SplitPlanError> {
        assert!(n >= 2, "split_at_midpoint: n must be >= 2");

        let start = self.parent_start();
        let end = self.parent_end();

        let mut points = Vec::new();
        Self::compute_midpoint_splits(start, end, n, &mut points);
        points.dedup();

        if points.is_empty() {
            return Err(SplitPlanError::NoViableMidpoint {
                start: start.to_vec().into_boxed_slice(),
                end: end.to_vec().into_boxed_slice(),
            });
        }

        self.split_at(&points, connector_extra_fn)
    }

    /// Split a manifest shard at a specific row boundary.
    ///
    /// ## Errors
    ///
    /// - `NotManifestShard` if parent isn't a manifest shard.
    /// - `ManifestRowOutOfRange` if `split_row` outside `(start_row, end_row)`.
    pub fn split_manifest_at_row(
        &self,
        split_row: u64,
        connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
    ) -> Result<SplitReplacePlan, SplitPlanError> {
        let (manifest_id, start_row, end_row) = match &self.parent_hint {
            ShardHint::Manifest {
                manifest_id,
                start_row,
                end_row,
            } => (*manifest_id, *start_row, *end_row),
            other => {
                return Err(SplitPlanError::NotManifestShard {
                    actual_hint: format!("{:?}", other),
                });
            }
        };

        if split_row <= start_row || split_row >= end_row {
            return Err(SplitPlanError::ManifestRowOutOfRange {
                split_row,
                start_row,
                end_row,
            });
        }

        let split_key =
            ManifestRowKey::new(manifest_id, split_row).encode();
        self.split_at(&[split_key], connector_extra_fn)
    }

    // ── SplitResidual planning ─────────────────────────────────────────

    /// Plan a residual split at an explicit byte-encoded boundary.
    ///
    /// Parent keeps `[parent.start, split_point)`, residual gets
    /// `[split_point, parent.end)`.
    pub fn residual_at(
        &self,
        split_point: Vec<u8>,
        parent_connector_extra: Vec<u8>,
        residual_connector_extra: Vec<u8>,
    ) -> Result<SplitResidualPlan, SplitPlanError> {
        self.validate_single_split_point(&split_point)?;

        let parent_start = self.parent_start();
        let parent_end = self.parent_end();

        // Parent keeps [start, split_point).
        let parent_hint =
            self.propagate_hint_safe(parent_start, &split_point);
        let parent_meta =
            ShardMetadata::new(parent_hint, parent_connector_extra);
        let parent_new_spec = ShardSpec::with_range_and_metadata(
            parent_start.to_vec(),
            split_point.clone(),
            parent_meta.encode(),
        );

        // Residual gets [split_point, end).
        let residual_hint =
            self.propagate_hint_safe(&split_point, parent_end);
        let residual_meta =
            ShardMetadata::new(residual_hint, residual_connector_extra);
        let residual_spec = ShardSpec::with_range_and_metadata(
            split_point,
            parent_end.to_vec(),
            residual_meta.encode(),
        );

        Ok(SplitResidualPlan {
            parent_new_spec,
            residual_spec,
            residual_cursor: Cursor::initial(),
        })
    }

    /// Plan a residual split at the current cursor position.
    ///
    /// The split point is `cursor.last_key`. Under `CursorSemantics::Completed`,
    /// last_key is the last key fully processed, so the parent range
    /// `[start, last_key)` excludes it — the residual will re-encounter
    /// it and skip via deduplication (idempotent processing).
    ///
    /// ## Errors
    ///
    /// - `CursorNotAdvanced` if cursor has no `last_key`.
    /// - `SplitPointOutOfRange` if `last_key` outside parent range.
    pub fn residual_at_cursor(
        &self,
        cursor: &Cursor,
        parent_connector_extra: Vec<u8>,
        residual_connector_extra: Vec<u8>,
    ) -> Result<SplitResidualPlan, SplitPlanError> {
        let last_key = cursor
            .last_key
            .as_ref()
            .ok_or(SplitPlanError::CursorNotAdvanced)?;

        self.residual_at(
            last_key.to_vec(),
            parent_connector_extra,
            residual_connector_extra,
        )
    }

    /// Plan a residual split for a manifest shard at a row boundary.
    pub fn residual_manifest_at_row(
        &self,
        split_row: u64,
        parent_connector_extra: Vec<u8>,
        residual_connector_extra: Vec<u8>,
    ) -> Result<SplitResidualPlan, SplitPlanError> {
        let (manifest_id, start_row, end_row) = match &self.parent_hint {
            ShardHint::Manifest {
                manifest_id,
                start_row,
                end_row,
            } => (*manifest_id, *start_row, *end_row),
            other => {
                return Err(SplitPlanError::NotManifestShard {
                    actual_hint: format!("{:?}", other),
                });
            }
        };

        if split_row <= start_row || split_row >= end_row {
            return Err(SplitPlanError::ManifestRowOutOfRange {
                split_row,
                start_row,
                end_row,
            });
        }

        let split_key =
            ManifestRowKey::new(manifest_id, split_row).encode();
        self.residual_at(
            split_key,
            parent_connector_extra,
            residual_connector_extra,
        )
    }

    // ── Internal helpers ───────────────────────────────────────────────

    /// Validate that all split points are strictly within the parent's
    /// range and in ascending order.
    fn validate_split_points(
        &self,
        points: &[Vec<u8>],
    ) -> Result<(), SplitPlanError> {
        let start = self.parent_start();
        let end = self.parent_end();

        for (i, point) in points.iter().enumerate() {
            // Must be strictly after parent start.
            // Note: `start == []` means "unbounded start" (−∞), but the empty
            // byte string is also the minimum key in lexicographic order. That
            // means we can compare directly and it correctly rejects `point == []`.
            if point.as_slice() <= start {
                return Err(SplitPlanError::SplitPointOutOfRange {
                    index: i,
                    point: point.clone().into_boxed_slice(),
                    range_start: start.to_vec().into_boxed_slice(),
                    range_end: end.to_vec().into_boxed_slice(),
                });
            }

            // Must be strictly before parent end.
            if !end.is_empty() && point.as_slice() >= end {
                return Err(SplitPlanError::SplitPointOutOfRange {
                    index: i,
                    point: point.clone().into_boxed_slice(),
                    range_start: start.to_vec().into_boxed_slice(),
                    range_end: end.to_vec().into_boxed_slice(),
                });
            }

            // Must be strictly after the previous point.
            if i > 0 && point.as_slice() <= points[i - 1].as_slice() {
                return Err(SplitPlanError::SplitPointsNotAscending {
                    index: i,
                    point: point.clone().into_boxed_slice(),
                    previous: points[i - 1].clone().into_boxed_slice(),
                });
            }
        }

        Ok(())
    }

    /// Validate a single split point for residual splits.
    fn validate_single_split_point(
        &self,
        point: &[u8],
    ) -> Result<(), SplitPlanError> {
        self.validate_split_points(&[point.to_vec()])
    }

    /// Propagate the parent hint to a child, falling back to Range.
    fn propagate_hint_safe(
        &self,
        child_start: &[u8],
        child_end: &[u8],
    ) -> ShardHint {
        propagate_hint_on_split(&self.parent_hint, child_start, child_end)
            .unwrap_or(ShardHint::Range)
    }

    /// Recursively compute midpoint split points.
    fn compute_midpoint_splits(
        start: &[u8],
        end: &[u8],
        n: usize,
        points: &mut Vec<Vec<u8>>,
    ) {
        if n <= 1 {
            return;
        }

        let mid = match byte_midpoint(start, end) {
            Some(m) => m,
            None => return,
        };

        let left_n = n / 2;
        let right_n = n - left_n;

        Self::compute_midpoint_splits(start, &mid, left_n, points);
        points.push(mid.clone());
        Self::compute_midpoint_splits(&mid, end, right_n, points);
    }
}

impl fmt::Debug for SplitPlanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitPlanner")
            .field(
                "parent_start",
                &format!(
                    "{} bytes",
                    self.parent_spec.key_range_start.len()
                ),
            )
            .field(
                "parent_end",
                &format!(
                    "{} bytes",
                    self.parent_spec.key_range_end.len()
                ),
            )
            .field("parent_hint", &self.parent_hint)
            .finish()
    }
}

// ============================================================================
// § SplitPlanError
// ============================================================================

/// Error from `SplitPlanner` methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitPlanError {
    /// No split points provided.
    NoSplitPoints,

    /// A split point is outside the parent's `(start, end)` range.
    SplitPointOutOfRange {
        index: usize,
        point: Box<[u8]>,
        range_start: Box<[u8]>,
        range_end: Box<[u8]>,
    },

    /// Split points are not in strictly ascending order.
    SplitPointsNotAscending {
        index: usize,
        point: Box<[u8]>,
        previous: Box<[u8]>,
    },

    /// Parent range too narrow for midpoint split.
    NoViableMidpoint {
        start: Box<[u8]>,
        end: Box<[u8]>,
    },

    /// Expected Manifest shard but got a different hint type.
    NotManifestShard {
        actual_hint: String,
    },

    /// Manifest row split point outside `(start_row, end_row)`.
    ManifestRowOutOfRange {
        split_row: u64,
        start_row: u64,
        end_row: u64,
    },

    /// Cursor has no `last_key` — cannot determine split position.
    CursorNotAdvanced,
}

impl fmt::Display for SplitPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSplitPoints => {
                write!(f, "no split points provided (need at least one)")
            }
            Self::SplitPointOutOfRange { index, .. } => {
                write!(
                    f,
                    "split point at index {} is outside parent range",
                    index
                )
            }
            Self::SplitPointsNotAscending { index, .. } => {
                write!(
                    f,
                    "split point at index {} is not ascending",
                    index
                )
            }
            Self::NoViableMidpoint { .. } => {
                write!(f, "parent range too narrow for midpoint split")
            }
            Self::NotManifestShard { actual_hint } => {
                write!(
                    f,
                    "expected Manifest shard, got {}",
                    actual_hint
                )
            }
            Self::ManifestRowOutOfRange {
                split_row,
                start_row,
                end_row,
            } => {
                write!(
                    f,
                    "manifest split_row {} outside ({}, {})",
                    split_row, start_row, end_row,
                )
            }
            Self::CursorNotAdvanced => {
                write!(
                    f,
                    "cursor has no last_key — cannot split at cursor position"
                )
            }
        }
    }
}

// ============================================================================
// § Convenience functions
// ============================================================================

/// Split a shard in half at the byte midpoint.
pub fn split_in_half(
    parent_spec: &ShardSpec,
    connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
) -> Result<SplitReplacePlan, SplitPlanError> {
    SplitPlanner::for_shard(parent_spec)
        .split_at_midpoint(2, connector_extra_fn)
}

/// Split a shard into N approximately equal parts.
pub fn split_into_n(
    parent_spec: &ShardSpec,
    n: usize,
    connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
) -> Result<SplitReplacePlan, SplitPlanError> {
    SplitPlanner::for_shard(parent_spec)
        .split_at_midpoint(n, connector_extra_fn)
}

/// Create a residual split at the cursor's current position.
pub fn residual_at_cursor(
    parent_spec: &ShardSpec,
    cursor: &Cursor,
    parent_connector_extra: Vec<u8>,
    residual_connector_extra: Vec<u8>,
) -> Result<SplitResidualPlan, SplitPlanError> {
    SplitPlanner::for_shard(parent_spec).residual_at_cursor(
        cursor,
        parent_connector_extra,
        residual_connector_extra,
    )
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::hint::{manifest_shard, prefix_shard, range_shard};
    use crate::shard::key_encoding::PathKey;

    /// Helper: create a range shard spec for testing.
    fn test_range_shard(start: &[u8], end: &[u8]) -> ShardSpec {
        range_shard(start.to_vec(), end.to_vec(), vec![])
    }

    /// Helper: create a prefix shard spec for testing.
    fn test_prefix_shard(prefix: &[u8]) -> ShardSpec {
        prefix_shard(prefix.to_vec(), vec![])
    }

    /// Helper: create a manifest shard spec for testing.
    fn test_manifest_shard(mid: u64, start: u64, end: u64) -> ShardSpec {
        manifest_shard(mid, start, end, vec![])
    }

    /// No-op connector extra.
    fn no_extra(_idx: usize, _start: &[u8], _end: &[u8]) -> Vec<u8> {
        vec![]
    }

    // ── SplitPlanner: basic split_at ──────────────────────────────────

    #[test]
    fn split_at_single_point() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let planner = SplitPlanner::for_shard(&parent);

        let plan = planner
            .split_at(&[b"mmm".to_vec()], no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);
        assert_eq!(
            plan.children[0].spec.key_range_start.as_ref(),
            b"aaa"
        );
        assert_eq!(
            plan.children[0].spec.key_range_end.as_ref(),
            b"mmm"
        );
        assert_eq!(
            plan.children[1].spec.key_range_start.as_ref(),
            b"mmm"
        );
        assert_eq!(
            plan.children[1].spec.key_range_end.as_ref(),
            b"zzz"
        );

        // Coverage check via B2.
        let child_specs: Vec<ShardSpec> =
            plan.children.iter().map(|c| c.spec.clone()).collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn split_at_multiple_points() {
        let parent = test_range_shard(b"a", b"z");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(
                &[b"f".to_vec(), b"m".to_vec(), b"t".to_vec()],
                no_extra,
            )
            .unwrap();

        assert_eq!(plan.children.len(), 4);

        // Verify contiguity.
        for window in plan.children.windows(2) {
            assert_eq!(
                window[0].spec.key_range_end,
                window[1].spec.key_range_start,
            );
        }

        assert_eq!(
            plan.children[0].spec.key_range_start.as_ref(),
            b"a"
        );
        assert_eq!(
            plan.children[3].spec.key_range_end.as_ref(),
            b"z"
        );
    }

    #[test]
    fn split_at_children_have_initial_cursors() {
        let parent = test_range_shard(b"a", b"z");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(&[b"m".to_vec()], no_extra)
            .unwrap();

        for child in &plan.children {
            assert!(child.cursor.is_initial());
        }
    }

    // ── SplitPlanner: validation errors ────────────────────────────────

    #[test]
    fn split_at_rejects_empty_points() {
        let parent = test_range_shard(b"a", b"z");
        let result =
            SplitPlanner::for_shard(&parent).split_at(&[], no_extra);
        assert!(matches!(result, Err(SplitPlanError::NoSplitPoints)));
    }

    #[test]
    fn split_at_rejects_point_before_start() {
        let parent = test_range_shard(b"m", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"a".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointOutOfRange { index: 0, .. })
        ));
    }

    #[test]
    fn split_at_rejects_point_at_start() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"a".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointOutOfRange { index: 0, .. })
        ));
    }

    #[test]
    fn split_at_rejects_point_at_start_when_start_unbounded() {
        // start == [] is an unbounded start; the split point must still be
        // strictly within the range, so [] is invalid (it's equal to start).
        let parent = test_range_shard(b"", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointOutOfRange { index: 0, .. })
        ));
    }

    #[test]
    fn split_at_rejects_point_at_end() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"z".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointOutOfRange { index: 0, .. })
        ));
    }

    #[test]
    fn split_at_rejects_point_after_end() {
        let parent = test_range_shard(b"a", b"m");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"z".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointOutOfRange { index: 0, .. })
        ));
    }

    #[test]
    fn split_at_rejects_non_ascending_points() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"m".to_vec(), b"f".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointsNotAscending {
                index: 1,
                ..
            })
        ));
    }

    #[test]
    fn split_at_rejects_duplicate_points() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"m".to_vec(), b"m".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointsNotAscending {
                index: 1,
                ..
            })
        ));
    }

    // ── SplitPlanner: hint propagation ─────────────────────────────────

    #[test]
    fn split_range_shard_children_get_range_hints() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(&[b"mmm".to_vec()], no_extra)
            .unwrap();

        for child in &plan.children {
            assert!(child.spec.decode_hint().unwrap().is_range());
        }
    }

    #[test]
    fn split_prefix_shard_children_demote_to_range() {
        let parent = test_prefix_shard(b"src/");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(&[b"src/m".to_vec()], no_extra)
            .unwrap();

        for child in &plan.children {
            let hint = child.spec.decode_hint().unwrap();
            assert!(hint.is_range(), "expected Range after prefix split");
        }
    }

    #[test]
    fn split_manifest_shard_children_get_manifest_hints() {
        let parent = test_manifest_shard(42, 0, 1000);
        let plan = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(500, no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);

        let h0 = plan.children[0].spec.decode_hint().unwrap();
        assert_eq!(h0.manifest_fields(), Some((42, 0, 500)));

        let h1 = plan.children[1].spec.decode_hint().unwrap();
        assert_eq!(h1.manifest_fields(), Some((42, 500, 1000)));
    }

    // ── SplitPlanner: defensive hint fallback ──────────────────────────

    #[test]
    fn corrupt_metadata_falls_back_to_range() {
        let parent = ShardSpec::with_range_and_metadata(
            b"aaa".to_vec(),
            b"zzz".to_vec(),
            vec![0xFF, 0xFF, 0xFF, 0xFF],
        );

        let planner = SplitPlanner::for_shard(&parent);
        assert!(planner.parent_hint().is_range());

        let plan = planner
            .split_at(&[b"mmm".to_vec()], no_extra)
            .unwrap();

        for child in &plan.children {
            assert!(child.spec.decode_hint().unwrap().is_range());
        }
    }

    // ── SplitPlanner: midpoint split ───────────────────────────────────

    #[test]
    fn split_at_midpoint_binary() {
        let parent = test_range_shard(b"\x00", b"\xff");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at_midpoint(2, no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);

        let child_specs: Vec<ShardSpec> =
            plan.children.iter().map(|c| c.spec.clone()).collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn split_at_midpoint_four_way() {
        let parent = test_range_shard(b"\x00\x00", b"\xff\xff");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at_midpoint(4, no_extra)
            .unwrap();

        assert!(plan.children.len() >= 2);
        assert!(plan.children.len() <= 4);

        let child_specs: Vec<ShardSpec> =
            plan.children.iter().map(|c| c.spec.clone()).collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn split_at_midpoint_narrow_range() {
        let parent = test_range_shard(b"\x00", b"\x01");
        let result = SplitPlanner::for_shard(&parent)
            .split_at_midpoint(2, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::NoViableMidpoint { .. })
        ));
    }

    // ── SplitPlanner: typed key split ──────────────────────────────────

    #[test]
    fn split_at_typed_key() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let split_key = PathKey::from_str("mmm");

        let plan = SplitPlanner::for_shard(&parent)
            .split_at_key(&split_key, no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);
        assert_eq!(
            plan.children[0].spec.key_range_end.as_ref(),
            b"mmm"
        );
        assert_eq!(
            plan.children[1].spec.key_range_start.as_ref(),
            b"mmm"
        );
    }

    // ── SplitPlanner: manifest-specific operations ─────────────────────

    #[test]
    fn split_manifest_at_row_basic() {
        let parent = test_manifest_shard(7, 0, 1000);
        let plan = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(500, no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);

        let expected_mid = ManifestRowKey::new(7, 500).encode();
        assert_eq!(
            plan.children[0].spec.key_range_end.as_ref(),
            expected_mid.as_slice()
        );
        assert_eq!(
            plan.children[1].spec.key_range_start.as_ref(),
            expected_mid.as_slice()
        );
    }

    #[test]
    fn split_manifest_at_row_rejects_non_manifest() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(500, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::NotManifestShard { .. })
        ));
    }

    #[test]
    fn split_manifest_at_row_rejects_out_of_range() {
        let parent = test_manifest_shard(7, 100, 500);

        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(100, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::ManifestRowOutOfRange {
                split_row: 100,
                ..
            })
        ));

        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(500, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::ManifestRowOutOfRange {
                split_row: 500,
                ..
            })
        ));

        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(999, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::ManifestRowOutOfRange {
                split_row: 999,
                ..
            })
        ));
    }

    // ── SplitPlanner: residual splits ──────────────────────────────────

    #[test]
    fn residual_at_explicit_point() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let plan = SplitPlanner::for_shard(&parent)
            .residual_at(
                b"mmm".to_vec(),
                b"parent-extra".to_vec(),
                b"residual-extra".to_vec(),
            )
            .unwrap();

        assert_eq!(
            plan.parent_new_spec.key_range_start.as_ref(),
            b"aaa"
        );
        assert_eq!(
            plan.parent_new_spec.key_range_end.as_ref(),
            b"mmm"
        );
        assert_eq!(
            plan.residual_spec.key_range_start.as_ref(),
            b"mmm"
        );
        assert_eq!(
            plan.residual_spec.key_range_end.as_ref(),
            b"zzz"
        );
        assert!(plan.residual_cursor.is_initial());

        // Coverage via B2.
        assert!(validate_residual_split(
            &parent,
            &plan.parent_new_spec,
            &plan.residual_spec,
        )
        .is_ok());

        // Connector extra propagated.
        let parent_meta =
            plan.parent_new_spec.decode_metadata().unwrap();
        assert_eq!(
            parent_meta.connector_extra.as_ref(),
            b"parent-extra"
        );

        let residual_meta =
            plan.residual_spec.decode_metadata().unwrap();
        assert_eq!(
            residual_meta.connector_extra.as_ref(),
            b"residual-extra"
        );
    }

    #[test]
    fn residual_at_cursor_basic() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let cursor = Cursor::with_last_key(b"mmm".to_vec());

        let plan = SplitPlanner::for_shard(&parent)
            .residual_at_cursor(&cursor, vec![], vec![])
            .unwrap();

        assert_eq!(
            plan.parent_new_spec.key_range_end.as_ref(),
            b"mmm"
        );
        assert_eq!(
            plan.residual_spec.key_range_start.as_ref(),
            b"mmm"
        );
    }

    #[test]
    fn residual_at_cursor_rejects_initial_cursor() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let cursor = Cursor::initial();

        let result = SplitPlanner::for_shard(&parent)
            .residual_at_cursor(&cursor, vec![], vec![]);
        assert!(matches!(
            result,
            Err(SplitPlanError::CursorNotAdvanced)
        ));
    }

    #[test]
    fn residual_at_cursor_rejects_out_of_range() {
        let parent = test_range_shard(b"mmm", b"zzz");
        let cursor = Cursor::with_last_key(b"aaa".to_vec());

        let result = SplitPlanner::for_shard(&parent)
            .residual_at_cursor(&cursor, vec![], vec![]);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointOutOfRange { .. })
        ));
    }

    // ── SplitPlanner: residual manifest split ──────────────────────────

    #[test]
    fn residual_manifest_at_row_basic() {
        let parent = test_manifest_shard(7, 0, 1000);
        let plan = SplitPlanner::for_shard(&parent)
            .residual_manifest_at_row(300, vec![], vec![])
            .unwrap();

        let ph = plan.parent_new_spec.decode_hint().unwrap();
        assert_eq!(ph.manifest_fields(), Some((7, 0, 300)));

        let rh = plan.residual_spec.decode_hint().unwrap();
        assert_eq!(rh.manifest_fields(), Some((7, 300, 1000)));

        assert!(validate_residual_split(
            &parent,
            &plan.parent_new_spec,
            &plan.residual_spec,
        )
        .is_ok());
    }

    #[test]
    fn residual_manifest_at_row_rejects_non_manifest() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .residual_manifest_at_row(500, vec![], vec![]);
        assert!(matches!(
            result,
            Err(SplitPlanError::NotManifestShard { .. })
        ));
    }

    #[test]
    fn residual_manifest_at_row_rejects_out_of_range() {
        let parent = test_manifest_shard(7, 100, 500);
        let result = SplitPlanner::for_shard(&parent)
            .residual_manifest_at_row(100, vec![], vec![]);
        assert!(matches!(
            result,
            Err(SplitPlanError::ManifestRowOutOfRange { .. })
        ));
    }

    // ── Convenience functions ──────────────────────────────────────────

    #[test]
    fn split_in_half_basic() {
        let parent = test_range_shard(b"\x00\x00", b"\xff\xff");
        let plan = split_in_half(&parent, no_extra).unwrap();

        assert_eq!(plan.children.len(), 2);
        let child_specs: Vec<ShardSpec> =
            plan.children.iter().map(|c| c.spec.clone()).collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn split_into_n_produces_correct_count() {
        let parent = test_range_shard(b"\x00", b"\xff");
        let plan = split_into_n(&parent, 4, no_extra).unwrap();

        assert!(plan.children.len() >= 2);
        assert!(plan.children.len() <= 4);
    }

    #[test]
    fn convenience_residual_at_cursor() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let cursor = Cursor::with_last_key(b"mmm".to_vec());

        let plan = residual_at_cursor(
            &parent,
            &cursor,
            vec![],
            vec![],
        )
        .unwrap();

        assert!(validate_residual_split(
            &parent,
            &plan.parent_new_spec,
            &plan.residual_spec,
        )
        .is_ok());
    }

    // ── Connector extra propagation ────────────────────────────────────

    #[test]
    fn split_at_with_per_child_extra() {
        let parent = test_range_shard(b"a", b"z");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(
                &[b"m".to_vec()],
                |idx, start, _end| {
                    format!("child-{}:start={}", idx, start.len())
                        .into_bytes()
                },
            )
            .unwrap();

        let meta0 = plan.children[0].spec.decode_metadata().unwrap();
        assert!(meta0.connector_extra.starts_with(b"child-0:"));

        let meta1 = plan.children[1].spec.decode_metadata().unwrap();
        assert!(meta1.connector_extra.starts_with(b"child-1:"));
    }

    // ── SplitPlanError Display ─────────────────────────────────────────

    #[test]
    fn split_plan_error_display() {
        let e = SplitPlanError::NoSplitPoints;
        assert!(format!("{}", e).contains("no split points"));

        let e = SplitPlanError::CursorNotAdvanced;
        assert!(format!("{}", e).contains("last_key"));

        let e = SplitPlanError::NotManifestShard {
            actual_hint: "Range".into(),
        };
        assert!(format!("{}", e).contains("Range"));

        let e = SplitPlanError::ManifestRowOutOfRange {
            split_row: 50,
            start_row: 100,
            end_row: 200,
        };
        assert!(format!("{}", e).contains("50"));

        let e = SplitPlanError::NoViableMidpoint {
            start: b"\x00".to_vec().into_boxed_slice(),
            end: b"\x01".to_vec().into_boxed_slice(),
        };
        assert!(format!("{}", e).contains("narrow"));
    }

    // ── Debug format ───────────────────────────────────────────────────

    #[test]
    fn planner_debug() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let planner = SplitPlanner::for_shard(&parent);
        let debug = format!("{:?}", planner);
        assert!(debug.contains("SplitPlanner"));
        assert!(debug.contains("3 bytes"));
    }

    // ── End-to-end ─────────────────────────────────────────────────────

    #[test]
    fn end_to_end_worker_overload_split() {
        // Simulate: worker gets a big range shard, decides to split.
        // Note: prefix shards with short prefixes often have too-narrow
        // ranges for midpoint splits (e.g., "data/" → "data0" is adjacent).
        // Use a range shard with sufficient width.
        let parent = test_range_shard(b"data/\x00", b"data/\xff");
        let plan = split_in_half(&parent, |_idx, start, end| {
            format!(
                "range:[{}..{})",
                String::from_utf8_lossy(start),
                String::from_utf8_lossy(end)
            )
            .into_bytes()
        })
        .unwrap();

        assert_eq!(plan.children.len(), 2);

        // Children get Range hints.
        for child in &plan.children {
            assert!(child.spec.decode_hint().unwrap().is_range());
        }

        // B2 coverage holds.
        let child_specs: Vec<ShardSpec> =
            plan.children.iter().map(|c| c.spec.clone()).collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn narrow_prefix_shard_midpoint_fails() {
        // Prefix shard "data/" → range [data/, data0) has adjacent
        // last bytes, so midpoint split is not viable.
        let parent = test_prefix_shard(b"data/");
        let result = split_in_half(&parent, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::NoViableMidpoint { .. })
        ));
    }

    #[test]
    fn end_to_end_manifest_worker_handoff() {
        // Worker processing manifest shard [rows 0..10000], processed
        // up to row 3000, wants to hand off the rest.
        let parent = test_manifest_shard(1, 0, 10000);
        let plan = SplitPlanner::for_shard(&parent)
            .residual_manifest_at_row(3000, vec![], vec![])
            .unwrap();

        // Parent shrinks to [0, 3000).
        let ph = plan.parent_new_spec.decode_hint().unwrap();
        assert_eq!(ph.manifest_fields(), Some((1, 0, 3000)));

        // Residual gets [3000, 10000).
        let rh = plan.residual_spec.decode_hint().unwrap();
        assert_eq!(rh.manifest_fields(), Some((1, 3000, 10000)));

        // B2 coverage holds.
        assert!(validate_residual_split(
            &parent,
            &plan.parent_new_spec,
            &plan.residual_spec,
        )
        .is_ok());
    }

    // ── Property-based test stubs ──────────────────────────────────────

    // TODO: proptest for split_at coverage:
    //   ∀ parent, valid points:
    //     validate_split_coverage(parent, children) == Ok(())
    //
    // TODO: proptest for split_at hint propagation:
    //   ∀ parent with Range hint: all children have Range hint.
    //   ∀ parent with Prefix hint: all children have Range hint.
    //   ∀ parent with Manifest hint, valid row split: children have Manifest.
    //
    // TODO: proptest for residual_at coverage:
    //   ∀ parent, valid split_point:
    //     validate_residual_split(parent, new_parent, residual) == Ok(())
    //
    // TODO: proptest for split_at_midpoint:
    //   ∀ parent where midpoint exists:
    //     plan.children.len() >= 2
    //     validate_split_coverage(parent, children) == Ok(())
}
