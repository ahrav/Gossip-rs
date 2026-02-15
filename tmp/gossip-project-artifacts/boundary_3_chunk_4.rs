//! Boundary â‘¢ â€” Shard Algebra & Keyspace Contract: Chunk 4 (DRAFT)
//!
//! Typed split algebra: connector-facing API for constructing
//! `SplitReplacePlan` and `SplitResidualPlan` (from Boundary â‘¡)
//! using typed keys, structured metadata, and automatic hint
//! propagation.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5), Boundary â‘¡
//! (chunks 1â€“5), and Boundary â‘¢ (chunks 1â€“3).
//!
//! ## Conceptual Model
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ Connector (Stage 3) â€” "this shard is too big"              â”‚
//! â”‚                                                            â”‚
//! â”‚   let plan = SplitPlanner::for_shard(&parent_spec)         â”‚
//! â”‚       .split_at_midpoint(extra_fn)?                        â”‚
//! â”‚       .into_replace_plan();         â† typed â†’ B2 plan      â”‚
//! â”‚                                                            â”‚
//! â”‚   // OR: split at a specific typed key                     â”‚
//! â”‚   let plan = SplitPlanner::for_shard(&parent_spec)         â”‚
//! â”‚       .split_at_key(&PathKey::from_str("src/m"))?          â”‚
//! â”‚       .into_replace_plan();                                â”‚
//! â”‚                                                            â”‚
//! â”‚   // OR: residual split (keep left, hand off right)        â”‚
//! â”‚   let plan = SplitPlanner::for_shard(&parent_spec)         â”‚
//! â”‚       .residual_at_cursor(&current_cursor)?                â”‚
//! â”‚       .into_residual_plan();                               â”‚
//! â”‚                                                            â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ Coordinator (Stage 2)                                      â”‚
//! â”‚                                                            â”‚
//! â”‚   coord.split_replace(now, tenant, lease, plan, op_id)?;   â”‚
//! â”‚   // validates: coverage, fence, lease, idempotency         â”‚
//! â”‚                                                            â”‚
//! â”‚   Coordinator sees only ShardSpec bytes.                    â”‚
//! â”‚   All type safety was ensured above the boundary.           â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```
//!
//! ## Design Decisions (locked)
//!
//! D3.15: Split planning is separated from split execution. The planner
//!        produces a B2 plan value; the connector then submits it to the
//!        coordinator. This separation means:
//!        - Planning is pure computation (no I/O, no lease needed).
//!        - Execution is atomic (the coordinator validates and applies).
//!        - Retries are trivial (resubmit the same plan with same OpId).
//!
//!        Reference: Spanner (Corbett et al., OSDI 2012) â€” split
//!        decisions are made by tablet servers but executed by the
//!        coordination layer. The split request is a declarative plan.
//!
//! D3.16: Hint propagation is automatic in the planner. The planner
//!        decodes the parent's hint from its metadata and applies the
//!        propagation rules from B3 chunk 2 (`propagate_hint_on_split`)
//!        to each child. Connectors do not manually propagate hints.
//!
//!        If the parent's hint cannot be decoded (corrupt metadata,
//!        unknown version), the planner falls back to `ShardHint::Range`
//!        for all children. This is safe because Range is the most
//!        conservative hint â€” it tells the connector "no domain
//!        assumptions, iterate the full byte range."
//!
//!        Reference: Defensive degradation pattern â€” when structured
//!        metadata is unavailable, fall back to the generic path rather
//!        than failing. FoundationDB subspace layer uses the same
//!        approach: if a subspace can't be decoded, the raw key range
//!        is still valid for iteration.
//!
//! D3.17: The planner validates split points before producing a plan.
//!        It checks:
//!        - Split point is strictly within `(parent.start, parent.end)`.
//!        - For manifest shards: split is on a row boundary.
//!        - For multi-way splits: points are strictly ascending.
//!
//!        The B2 coordinator ALSO validates (via validate_split_coverage),
//!        so this is defense-in-depth. But catching errors at plan time
//!        gives the connector better diagnostics than a coordinator
//!        rejection.
//!
//!        Reference: Principle of "fail early, fail loud" â€” Tiger Style
//!        (TigerBeetle Design Document).
//!
//! D3.18: `SplitPlanner` is NOT generic over key type. Split points are
//!        provided as raw `Vec<u8>` (encoded bytes) or via helper methods
//!        that accept typed keys and encode them. This matches the pattern
//!        in B3 chunk 3 (TypedShardBuilder) â€” the builder is concrete,
//!        not generic.
//!
//!        Rationale: A generic planner would couple the coordinator's
//!        error types to key schema types, violating the boundary.
//!
//! D3.19: Connector-extra metadata for child shards is provided via a
//!        closure `Fn(usize, &[u8], &[u8]) -> Vec<u8>` that receives
//!        (child_index, child_start, child_end). This allows the
//!        connector to compute per-child metadata without the planner
//!        needing to understand the metadata schema.

// Assumes all types from Boundaries â‘ , â‘¡, and â‘¢ chunks 1â€“3 are in scope.

use core::fmt;

// ============================================================================
// Â§ Chunk 4: Typed Split Algebra
// ============================================================================

// ---------------------------------------------------------------------------
// Â§4.1 SplitPlanner â€” connector-facing split plan construction
// ---------------------------------------------------------------------------

/// Planner for constructing split operations on an existing shard.
///
/// ## Lifecycle
///
/// ```text
/// 1. Create:   SplitPlanner::for_shard(&parent_spec)
/// 2. Plan:     .split_at(points)  OR  .split_at_midpoint()  OR  .residual_at(point)
/// 3. Extract:  .into_replace_plan()  OR  .into_residual_plan()
/// 4. Submit:   coordinator.split_replace(... plan ...) / split_residual(...)
/// ```
///
/// The planner holds a reference to the parent's `ShardSpec` and its
/// decoded hint. It produces B2-level plan types (`SplitReplacePlan` or
/// `SplitResidualPlan`) with correct hint propagation.
///
/// ## Thread Safety
///
/// Not `Sync`. Split planning is a per-worker, per-shard decision.
///
/// ## Invariants
///
/// **Safety (hint propagation)**: Every child shard in the plan has a
/// hint derived from the parent via `propagate_hint_on_split`. If
/// propagation fails, the child gets `ShardHint::Range`.
///
/// **Safety (coverage preservation)**: The produced plan, if accepted
/// by the coordinator, preserves the parent's key range coverage.
/// This is enforced by construction (children tile the parent) and
/// verified by B2's `validate_split_coverage`.
///
/// **Safety (plan purity)**: The planner performs no I/O, no network
/// calls, no blocking. It is pure computation over byte ranges.
pub struct SplitPlanner {
    /// Parent shard's spec (key range + metadata).
    parent_spec: ShardSpec,

    /// Decoded hint from the parent, or Range on decode failure.
    parent_hint: ShardHint,

    /// Parent's connector_extra, passed through to children by default.
    parent_connector_extra: Box<[u8]>,
}

impl SplitPlanner {
    /// Create a planner for splitting an existing shard.
    ///
    /// Decodes the parent's hint from its metadata. If decoding fails
    /// (corrupt metadata, unknown version), falls back to
    /// `ShardHint::Range` and empty connector_extra.
    ///
    /// This is defensive: a corrupt parent hint should not prevent
    /// splitting. The children will simply get Range hints and the
    /// connector will iterate the full byte range.
    pub fn for_shard(parent_spec: &ShardSpec) -> Self {
        let (parent_hint, parent_connector_extra) = match parent_spec.decode_metadata() {
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

    // â”€â”€ SplitReplace planning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Split the parent at one or more explicit byte-encoded split points.
    ///
    /// Produces a `SplitReplacePlan` with `points.len() + 1` children
    /// whose ranges tile the parent: `[start, p0), [p0, p1), ..., [pN, end)`.
    ///
    /// ## Arguments
    ///
    /// * `points` â€” Split boundaries, each strictly within
    ///   `(parent.start, parent.end)`. Must be in ascending order.
    /// * `connector_extra_fn` â€” Called for each child with
    ///   `(child_index, child_start, child_end)` to produce the
    ///   child's connector_extra metadata.
    ///
    /// ## Errors
    ///
    /// Returns `SplitPlanError` if:
    /// - `points` is empty (need at least one split point).
    /// - A point is outside `(parent.start, parent.end)`.
    /// - Points are not in strictly ascending order.
    /// - A point equals parent.start or parent.end.
    pub fn split_at(
        &self,
        points: &[Vec<u8>],
        connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
    ) -> Result<SplitReplacePlan, SplitPlanError> {
        // Validate split points.
        if points.is_empty() {
            return Err(SplitPlanError::NoSplitPoints);
        }

        self.validate_split_points(points)?;

        // Build the child boundary sequence: [start, p0, p1, ..., pN, end].
        let mut boundaries: Vec<&[u8]> = Vec::with_capacity(points.len() + 2);
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

            let child_hint = self.propagate_hint_safe(child_start, child_end);
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
    ///
    /// Convenience wrapper: encodes the key and calls `split_at` with
    /// a single split point.
    pub fn split_at_key<K: KeyEncoding>(
        &self,
        key: &K,
        connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
    ) -> Result<SplitReplacePlan, SplitPlanError> {
        let encoded = key.encode();
        self.split_at(&[encoded], connector_extra_fn)
    }

    /// Split the parent at Nâˆ’1 equally-spaced midpoints, producing N children.
    ///
    /// Uses `byte_midpoint` recursively. If the range is too narrow
    /// to produce N distinct children, produces fewer.
    ///
    /// ## Errors
    ///
    /// Returns `SplitPlanError::NoViableMidpoint` if the parent's range
    /// is too narrow to split at all (adjacent keys).
    pub fn split_at_midpoint(
        &self,
        n: usize,
        connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
    ) -> Result<SplitReplacePlan, SplitPlanError> {
        assert!(n >= 2, "split_at_midpoint: n must be >= 2");

        let start = self.parent_start();
        let end = self.parent_end();

        // Compute n-1 split points via recursive bisection.
        let mut points = Vec::new();
        Self::compute_midpoint_splits(start, end, n, &mut points);

        // Deduplicate (narrow ranges may produce duplicate midpoints).
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
    /// Only valid when the parent has a `ShardHint::Manifest` hint.
    /// Produces two children:
    /// - `[manifest_id, parent_start_row .. split_row)`
    /// - `[manifest_id, split_row .. parent_end_row)`
    ///
    /// ## Errors
    ///
    /// - `SplitPlanError::NotManifestShard` if parent isn't a manifest shard.
    /// - `SplitPlanError::ManifestRowOutOfRange` if `split_row` is outside
    ///   `(parent_start_row, parent_end_row)`.
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

        let split_key = ManifestRowKey::new(manifest_id, split_row).encode();
        self.split_at(&[split_key], connector_extra_fn)
    }

    // â”€â”€ SplitResidual planning â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Plan a residual split at an explicit byte-encoded boundary.
    ///
    /// The parent keeps `[parent.start, split_point)` and the residual
    /// gets `[split_point, parent.end)`.
    ///
    /// ## Arguments
    ///
    /// * `split_point` â€” Boundary between parent and residual, strictly
    ///   within `(parent.start, parent.end)`.
    /// * `parent_connector_extra` â€” Updated connector_extra for the
    ///   shrunk parent (may differ from original if the connector needs
    ///   to adjust bookkeeping).
    /// * `residual_connector_extra` â€” Connector_extra for the new
    ///   residual shard.
    ///
    /// ## Cursor Handling
    ///
    /// The residual gets `Cursor::initial()` â€” it has no progress yet.
    /// The parent keeps its existing cursor (managed by the connector,
    /// not by this planner). The coordinator does NOT change the parent's
    /// cursor on SplitResidual â€” it only shrinks the parent's spec.
    ///
    /// ## Errors
    ///
    /// Returns `SplitPlanError` if `split_point` is not strictly within
    /// the parent's range.
    pub fn residual_at(
        &self,
        split_point: Vec<u8>,
        parent_connector_extra: Vec<u8>,
        residual_connector_extra: Vec<u8>,
    ) -> Result<SplitResidualPlan, SplitPlanError> {
        self.validate_single_split_point(&split_point)?;

        let parent_start = self.parent_start();
        let parent_end = self.parent_end();

        // Parent keeps [start, split_point) with propagated hint.
        let parent_hint = self.propagate_hint_safe(parent_start, &split_point);
        let parent_meta = ShardMetadata::new(parent_hint, parent_connector_extra);
        let parent_new_spec = ShardSpec::with_range_and_metadata(
            parent_start.to_vec(),
            split_point.clone(),
            parent_meta.encode(),
        );

        // Residual gets [split_point, end) with propagated hint.
        let residual_hint = self.propagate_hint_safe(&split_point, parent_end);
        let residual_meta = ShardMetadata::new(residual_hint, residual_connector_extra);
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
    /// This is the most common residual split: a worker has processed
    /// up to `cursor.last_key` and wants to hand off everything beyond
    /// it. The split point is the byte AFTER `cursor.last_key`.
    ///
    /// ## Semantics
    ///
    /// The split point is `cursor.last_key` itself (NOT last_key + 1).
    /// Why: the parent's range becomes `[parent.start, last_key)`, which
    /// does NOT include `last_key`. But wait â€” hasn't the worker already
    /// processed `last_key`?
    ///
    /// Yes. Under `CursorSemantics::Completed`, `last_key` is the last
    /// key fully processed. So the parent range `[start, last_key)` is
    /// actually MISSING the last processed key. This is correct because:
    ///
    /// 1. The parent's cursor already records that `last_key` was processed.
    /// 2. The residual's range is `[last_key, end)`, which INCLUDES
    ///    `last_key` â€” but the residual will re-encounter it during
    ///    iteration and skip it via deduplication (idempotent processing).
    ///
    /// This design avoids the need for a `successor(last_key)` operation
    /// that would require knowing the key schema at the byte level.
    ///
    /// ## Alternative: cursor.last_key as split point
    ///
    /// We deliberately use `last_key` rather than computing `last_key + 1`
    /// because:
    /// - `successor(bytes)` is not always well-defined for variable-length
    ///   keys (what's the successor of `b"abc"`? `b"abc\x00"`? `b"abd"`?).
    /// - The dedup layer (content-addressed scan result IDs from Â§5.2)
    ///   already handles re-processing.
    /// - This is simpler to reason about: the split point is always a
    ///   value we KNOW exists (it was in the last checkpoint).
    ///
    /// ## Errors
    ///
    /// Returns `SplitPlanError::CursorNotAdvanced` if the cursor has
    /// no `last_key` (cannot split at an unknown position).
    ///
    /// Returns `SplitPlanError::SplitPointOutOfRange` if `last_key` is
    /// not within `(parent.start, parent.end)`.
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
    ///
    /// Parent keeps `[manifest_id, start_row .. split_row)`,
    /// residual gets `[manifest_id, split_row .. end_row)`.
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

        let split_key = ManifestRowKey::new(manifest_id, split_row).encode();
        self.residual_at(
            split_key,
            parent_connector_extra,
            residual_connector_extra,
        )
    }

    // â”€â”€ Internal helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Validate that all split points are strictly within the parent's
    /// range and in ascending order.
    fn validate_split_points(&self, points: &[Vec<u8>]) -> Result<(), SplitPlanError> {
        let start = self.parent_start();
        let end = self.parent_end();

        for (i, point) in points.iter().enumerate() {
            // Must be strictly after parent start.
            if !start.is_empty() && point.as_slice() <= start {
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
    fn validate_single_split_point(&self, point: &[u8]) -> Result<(), SplitPlanError> {
        self.validate_split_points(&[point.to_vec()])
    }

    /// Propagate the parent hint to a child, falling back to Range
    /// on any error.
    ///
    /// This is the defensive wrapper around `propagate_hint_on_split`
    /// from B3 chunk 2. Propagation can fail for Manifest shards if
    /// the child boundaries don't decode as ManifestRowKeys. In that
    /// case, Range is a safe fallback.
    fn propagate_hint_safe(&self, child_start: &[u8], child_end: &[u8]) -> ShardHint {
        propagate_hint_on_split(&self.parent_hint, child_start, child_end)
            .unwrap_or(ShardHint::Range)
    }

    /// Recursively compute midpoint split points.
    ///
    /// Same algorithm as TypedShardBuilder::compute_split_points
    /// (chunk 3), factored here for reuse.
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
            None => return, // Keys too close to split further.
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
            .field("parent_start", &format!("{} bytes", self.parent_spec.key_range_start.len()))
            .field("parent_end", &format!("{} bytes", self.parent_spec.key_range_end.len()))
            .field("parent_hint", &self.parent_hint)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Â§4.2 SplitPlanError â€” planner-level error type
// ---------------------------------------------------------------------------

/// Error from `SplitPlanner` methods.
///
/// These are connector-side planning errors, caught before submission
/// to the coordinator. The coordinator performs its own validation
/// (via `validate_split_coverage`), so these are defense-in-depth
/// diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitPlanError {
    /// No split points provided. Need at least one to create â‰¥ 2 children.
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

    /// The parent's key range is too narrow for a midpoint split.
    /// The keys are adjacent or identical â€” no byte string lies between them.
    NoViableMidpoint {
        start: Box<[u8]>,
        end: Box<[u8]>,
    },

    /// Attempted a manifest-specific operation on a non-manifest shard.
    NotManifestShard {
        actual_hint: String,
    },

    /// Manifest row split point is outside `(start_row, end_row)`.
    ManifestRowOutOfRange {
        split_row: u64,
        start_row: u64,
        end_row: u64,
    },

    /// Attempted `residual_at_cursor` but cursor has no `last_key`.
    CursorNotAdvanced,
}

impl fmt::Display for SplitPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSplitPoints => {
                write!(f, "no split points provided (need at least one)")
            }
            Self::SplitPointOutOfRange { index, .. } => {
                write!(f, "split point at index {} is outside parent range", index)
            }
            Self::SplitPointsNotAscending { index, .. } => {
                write!(f, "split point at index {} is not ascending", index)
            }
            Self::NoViableMidpoint { .. } => {
                write!(f, "parent range too narrow for midpoint split")
            }
            Self::NotManifestShard { actual_hint } => {
                write!(f, "expected Manifest shard, got {}", actual_hint)
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
                write!(f, "cursor has no last_key â€” cannot split at cursor position")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Â§4.3 Convenience: common split patterns
// ---------------------------------------------------------------------------

/// Split a shard in half at the byte midpoint.
///
/// This is the simplest split: one parent becomes two children of
/// approximately equal byte-width.
///
/// Returns the `SplitReplacePlan` ready for `coordinator.split_replace()`.
///
/// ## Errors
///
/// Returns `SplitPlanError::NoViableMidpoint` if the range is too
/// narrow to split.
pub fn split_in_half(
    parent_spec: &ShardSpec,
    connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
) -> Result<SplitReplacePlan, SplitPlanError> {
    SplitPlanner::for_shard(parent_spec)
        .split_at_midpoint(2, connector_extra_fn)
}

/// Split a shard into N approximately equal parts.
///
/// Convenience wrapper around `SplitPlanner::split_at_midpoint`.
pub fn split_into_n(
    parent_spec: &ShardSpec,
    n: usize,
    connector_extra_fn: impl Fn(usize, &[u8], &[u8]) -> Vec<u8>,
) -> Result<SplitReplacePlan, SplitPlanError> {
    SplitPlanner::for_shard(parent_spec)
        .split_at_midpoint(n, connector_extra_fn)
}

/// Create a residual split at the cursor's current position.
///
/// The worker keeps the left portion (already partially processed),
/// the residual gets the right portion (unprocessed).
///
/// Convenience wrapper around `SplitPlanner::residual_at_cursor`.
pub fn residual_at_cursor(
    parent_spec: &ShardSpec,
    cursor: &Cursor,
    parent_connector_extra: Vec<u8>,
    residual_connector_extra: Vec<u8>,
) -> Result<SplitResidualPlan, SplitPlanError> {
    SplitPlanner::for_shard(parent_spec)
        .residual_at_cursor(cursor, parent_connector_extra, residual_connector_extra)
}

// ---------------------------------------------------------------------------
// Â§4.4 Split invariants for chunk 4
// ---------------------------------------------------------------------------

//! ## Chunk 4 Invariant Additions
//!
//! These extend the B3 invariant catalog from chunk 3.
//!
//! ### Safety Invariants
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ ID          â”‚ Statement                                              â”‚ Enforced By          â”‚ Verification                   â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S17  â”‚ SplitPlanner hint propagation: every child in a        â”‚ propagate_hint_safe()â”‚ Unit test: split prefix shard  â”‚
//! â”‚             â”‚ produced plan has a hint derived from the parent via    â”‚                      â”‚ â†’ children get Range hints.    â”‚
//! â”‚             â”‚ propagate_hint_on_split, or Range on failure.          â”‚                      â”‚ Split manifest â†’ children get  â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ Manifest with sub-ranges.      â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S18  â”‚ SplitPlanner coverage: for split_at(points), the       â”‚ split_at()           â”‚ Property-based test:           â”‚
//! â”‚             â”‚ children tile [parent.start, parent.end) with no gaps  â”‚                      â”‚ âˆ€ valid points:                â”‚
//! â”‚             â”‚ and no overlaps.                                       â”‚                      â”‚ validate_split_coverage(parent,â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚   children) == Ok(())          â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S19  â”‚ SplitPlanner point validation: split_at rejects points â”‚ validate_split_      â”‚ Unit tests for each rejection  â”‚
//! â”‚             â”‚ outside (start, end) and non-ascending sequences.      â”‚ points()             â”‚ case.                          â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S20  â”‚ Residual split cursor safety: residual_at_cursor       â”‚ residual_at_cursor() â”‚ Unit test: initial cursor      â”‚
//! â”‚             â”‚ rejects cursors with no last_key (cannot determine     â”‚                      â”‚ â†’ CursorNotAdvanced error.     â”‚
//! â”‚             â”‚ split position).                                       â”‚                      â”‚                                â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S21  â”‚ Manifest split alignment: split_manifest_at_row        â”‚ split_manifest_      â”‚ Unit test: split at row        â”‚
//! â”‚             â”‚ produces children whose key_range boundaries exactly   â”‚ at_row()             â”‚ boundary â†’ key ranges match    â”‚
//! â”‚             â”‚ match ManifestRowKey::encode() for the split row.      â”‚                      â”‚ ManifestRowKey encoding.       â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S22  â”‚ Defensive hint fallback: if parent metadata cannot be  â”‚ SplitPlanner::       â”‚ Unit test: corrupt metadata    â”‚
//! â”‚             â”‚ decoded, planner uses Range hint (never panics).       â”‚ for_shard()          â”‚ â†’ planner succeeds with Range  â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ hints on all children.         â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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

    /// No-op connector extra â€” every child gets empty extra.
    fn no_extra(_idx: usize, _start: &[u8], _end: &[u8]) -> Vec<u8> {
        vec![]
    }

    // â”€â”€ SplitPlanner: basic split_at â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_at_single_point() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let planner = SplitPlanner::for_shard(&parent);

        let plan = planner
            .split_at(&[b"mmm".to_vec()], no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);
        assert_eq!(plan.children[0].spec.key_range_start.as_ref(), b"aaa");
        assert_eq!(plan.children[0].spec.key_range_end.as_ref(), b"mmm");
        assert_eq!(plan.children[1].spec.key_range_start.as_ref(), b"mmm");
        assert_eq!(plan.children[1].spec.key_range_end.as_ref(), b"zzz");

        // Coverage check via B2.
        let child_specs: Vec<ShardSpec> = plan.children.iter()
            .map(|c| c.spec.clone())
            .collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn split_at_multiple_points() {
        let parent = test_range_shard(b"a", b"z");
        let planner = SplitPlanner::for_shard(&parent);

        let plan = planner
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

        // Verify endpoints.
        assert_eq!(plan.children[0].spec.key_range_start.as_ref(), b"a");
        assert_eq!(plan.children[3].spec.key_range_end.as_ref(), b"z");
    }

    // â”€â”€ SplitPlanner: validation errors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_at_rejects_empty_points() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[], no_extra);
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
    fn split_at_rejects_non_ascending_points() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"m".to_vec(), b"f".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointsNotAscending { index: 1, .. })
        ));
    }

    #[test]
    fn split_at_rejects_duplicate_points() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_at(&[b"m".to_vec(), b"m".to_vec()], no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointsNotAscending { index: 1, .. })
        ));
    }

    // â”€â”€ SplitPlanner: hint propagation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_range_shard_children_get_range_hints() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(&[b"mmm".to_vec()], no_extra)
            .unwrap();

        for child in &plan.children {
            let hint = child.spec.decode_hint().unwrap();
            assert!(hint.is_range());
        }
    }

    #[test]
    fn split_prefix_shard_children_demote_to_range() {
        let parent = test_prefix_shard(b"src/");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(&[b"src/m".to_vec()], no_extra)
            .unwrap();

        // Prefix â†’ Range on split (D3.11 from chunk 2).
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

    // â”€â”€ SplitPlanner: defensive hint fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn corrupt_metadata_falls_back_to_range() {
        // Construct a ShardSpec with garbage metadata.
        let parent = ShardSpec::with_range_and_metadata(
            b"aaa".to_vec(),
            b"zzz".to_vec(),
            vec![0xFF, 0xFF, 0xFF, 0xFF], // invalid
        );

        let planner = SplitPlanner::for_shard(&parent);
        assert!(planner.parent_hint().is_range()); // Fallback to Range.

        let plan = planner
            .split_at(&[b"mmm".to_vec()], no_extra)
            .unwrap();

        for child in &plan.children {
            assert!(child.spec.decode_hint().unwrap().is_range());
        }
    }

    // â”€â”€ SplitPlanner: midpoint split â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_at_midpoint_binary() {
        let parent = test_range_shard(b"\x00", b"\xff");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at_midpoint(2, no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);

        // Children tile the parent.
        let child_specs: Vec<ShardSpec> = plan.children.iter()
            .map(|c| c.spec.clone())
            .collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn split_at_midpoint_narrow_range() {
        // Adjacent keys â€” cannot split.
        let parent = test_range_shard(b"\x00", b"\x01");
        let result = SplitPlanner::for_shard(&parent)
            .split_at_midpoint(2, no_extra);
        assert!(matches!(result, Err(SplitPlanError::NoViableMidpoint { .. })));
    }

    // â”€â”€ SplitPlanner: typed key split â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_at_typed_key() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let split_key = PathKey::from_str("mmm");

        let plan = SplitPlanner::for_shard(&parent)
            .split_at_key(&split_key, no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);
        assert_eq!(plan.children[0].spec.key_range_end.as_ref(), b"mmm");
        assert_eq!(plan.children[1].spec.key_range_start.as_ref(), b"mmm");
    }

    // â”€â”€ SplitPlanner: manifest-specific operations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_manifest_at_row_basic() {
        let parent = test_manifest_shard(7, 0, 1000);
        let plan = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(500, no_extra)
            .unwrap();

        assert_eq!(plan.children.len(), 2);

        // Verify key ranges match ManifestRowKey encoding.
        let expected_mid = ManifestRowKey::new(7, 500).encode();
        assert_eq!(plan.children[0].spec.key_range_end.as_ref(), expected_mid.as_slice());
        assert_eq!(plan.children[1].spec.key_range_start.as_ref(), expected_mid.as_slice());
    }

    #[test]
    fn split_manifest_at_row_rejects_non_manifest() {
        let parent = test_range_shard(b"a", b"z");
        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(500, no_extra);
        assert!(matches!(result, Err(SplitPlanError::NotManifestShard { .. })));
    }

    #[test]
    fn split_manifest_at_row_rejects_out_of_range() {
        let parent = test_manifest_shard(7, 100, 500);

        // At start boundary â€” not strictly within.
        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(100, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::ManifestRowOutOfRange { split_row: 100, .. })
        ));

        // At end boundary.
        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(500, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::ManifestRowOutOfRange { split_row: 500, .. })
        ));

        // Beyond end.
        let result = SplitPlanner::for_shard(&parent)
            .split_manifest_at_row(999, no_extra);
        assert!(matches!(
            result,
            Err(SplitPlanError::ManifestRowOutOfRange { split_row: 999, .. })
        ));
    }

    // â”€â”€ SplitPlanner: residual splits â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

        // Parent shrinks to [aaa, mmm).
        assert_eq!(plan.parent_new_spec.key_range_start.as_ref(), b"aaa");
        assert_eq!(plan.parent_new_spec.key_range_end.as_ref(), b"mmm");

        // Residual covers [mmm, zzz).
        assert_eq!(plan.residual_spec.key_range_start.as_ref(), b"mmm");
        assert_eq!(plan.residual_spec.key_range_end.as_ref(), b"zzz");

        // Residual cursor is initial.
        assert!(plan.residual_cursor.is_initial());

        // Coverage via B2.
        assert!(validate_residual_split(
            &parent,
            &plan.parent_new_spec,
            &plan.residual_spec,
        ).is_ok());

        // Connector extra propagated.
        let parent_meta = plan.parent_new_spec.decode_metadata().unwrap();
        assert_eq!(parent_meta.connector_extra.as_ref(), b"parent-extra");

        let residual_meta = plan.residual_spec.decode_metadata().unwrap();
        assert_eq!(residual_meta.connector_extra.as_ref(), b"residual-extra");
    }

    #[test]
    fn residual_at_cursor_basic() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let cursor = Cursor::with_last_key(b"mmm".to_vec());

        let plan = SplitPlanner::for_shard(&parent)
            .residual_at_cursor(&cursor, vec![], vec![])
            .unwrap();

        assert_eq!(plan.parent_new_spec.key_range_end.as_ref(), b"mmm");
        assert_eq!(plan.residual_spec.key_range_start.as_ref(), b"mmm");
    }

    #[test]
    fn residual_at_cursor_rejects_initial_cursor() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let cursor = Cursor::initial();

        let result = SplitPlanner::for_shard(&parent)
            .residual_at_cursor(&cursor, vec![], vec![]);
        assert!(matches!(result, Err(SplitPlanError::CursorNotAdvanced)));
    }

    #[test]
    fn residual_at_cursor_rejects_out_of_range() {
        let parent = test_range_shard(b"mmm", b"zzz");
        let cursor = Cursor::with_last_key(b"aaa".to_vec()); // before start

        let result = SplitPlanner::for_shard(&parent)
            .residual_at_cursor(&cursor, vec![], vec![]);
        assert!(matches!(
            result,
            Err(SplitPlanError::SplitPointOutOfRange { .. })
        ));
    }

    // â”€â”€ SplitPlanner: residual manifest split â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn residual_manifest_at_row_basic() {
        let parent = test_manifest_shard(7, 0, 1000);
        let plan = SplitPlanner::for_shard(&parent)
            .residual_manifest_at_row(300, vec![], vec![])
            .unwrap();

        // Parent hint: manifest (7, 0, 300).
        let ph = plan.parent_new_spec.decode_hint().unwrap();
        assert_eq!(ph.manifest_fields(), Some((7, 0, 300)));

        // Residual hint: manifest (7, 300, 1000).
        let rh = plan.residual_spec.decode_hint().unwrap();
        assert_eq!(rh.manifest_fields(), Some((7, 300, 1000)));

        // Coverage via B2.
        assert!(validate_residual_split(
            &parent,
            &plan.parent_new_spec,
            &plan.residual_spec,
        ).is_ok());
    }

    // â”€â”€ Convenience functions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_in_half_basic() {
        let parent = test_range_shard(b"\x00\x00", b"\xff\xff");
        let plan = split_in_half(&parent, no_extra).unwrap();

        assert_eq!(plan.children.len(), 2);
        let child_specs: Vec<ShardSpec> = plan.children.iter()
            .map(|c| c.spec.clone())
            .collect();
        assert!(validate_split_coverage(&parent, &child_specs).is_ok());
    }

    #[test]
    fn split_into_n_produces_correct_count() {
        let parent = test_range_shard(b"\x00", b"\xff");
        let plan = split_into_n(&parent, 4, no_extra).unwrap();

        // May produce fewer than 4 if midpoints collapse, but at least 2.
        assert!(plan.children.len() >= 2);
        assert!(plan.children.len() <= 4);
    }

    #[test]
    fn residual_at_cursor_convenience() {
        let parent = test_range_shard(b"aaa", b"zzz");
        let cursor = Cursor::with_last_key(b"mmm".to_vec());

        let plan = residual_at_cursor(&parent, &cursor, vec![], vec![]).unwrap();

        assert!(validate_residual_split(
            &parent,
            &plan.parent_new_spec,
            &plan.residual_spec,
        ).is_ok());
    }

    // â”€â”€ Connector extra propagation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_at_with_per_child_extra() {
        let parent = test_range_shard(b"a", b"z");
        let plan = SplitPlanner::for_shard(&parent)
            .split_at(
                &[b"m".to_vec()],
                |idx, start, _end| {
                    format!("child-{}:start={}", idx, start.len()).into_bytes()
                },
            )
            .unwrap();

        let meta0 = plan.children[0].spec.decode_metadata().unwrap();
        assert!(meta0.connector_extra.starts_with(b"child-0:"));

        let meta1 = plan.children[1].spec.decode_metadata().unwrap();
        assert!(meta1.connector_extra.starts_with(b"child-1:"));
    }

    // â”€â”€ Property-based test stubs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: proptest for split_at coverage:
    //   âˆ€ parent, valid points:
    //     validate_split_coverage(parent, children) == Ok(())
    //
    // TODO: proptest for split_at hint propagation:
    //   âˆ€ parent with Range hint: all children have Range hint.
    //   âˆ€ parent with Prefix hint: all children have Range hint.
    //   âˆ€ parent with Manifest hint, valid row split: children have Manifest.
    //
    // TODO: proptest for residual_at coverage:
    //   âˆ€ parent, valid split_point:
    //     validate_residual_split(parent, new_parent, residual) == Ok(())
    //
    // TODO: proptest for split_at_midpoint:
    //   âˆ€ parent where midpoint exists:
    //     plan.children.len() >= 2
    //     validate_split_coverage(parent, children) == Ok(())
    //
    // TODO: proptest for manifest split alignment:
    //   âˆ€ manifest shard (id, s, e), valid split_row:
    //     child boundaries == ManifestRowKey::encode(id, split_row)
}
