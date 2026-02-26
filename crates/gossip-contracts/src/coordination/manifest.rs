//! Shard manifest input type and validation for run registration.
//!
//! [`InitialShardInput`] is the borrowed entry type for the initial shard
//! manifest passed to `register_shards`. [`validate_manifest`] enforces
//! structural constraints (uniqueness, bounded ranges, cursor bounds) before
//! any records are created in the coordination layer.

use std::fmt;

use crate::coordination::cursor::{CursorUpdate, MAX_KEY_SIZE};
use crate::coordination::shard_spec::{ShardSpec, ShardSpecRef};
use crate::identity::ShardId;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of shards in a single `register_shards` call (SEC-3).
///
/// Prevents resource exhaustion from a single API call creating unbounded
/// shard records. Checked as the FIRST validation step in `validate_manifest`.
pub const MAX_INITIAL_SHARDS: usize = 10_000;

const _: () = assert!(MAX_INITIAL_SHARDS > 0);

// ============================================================================
// InitialShardInput
// ============================================================================

/// A borrowed shard registration input for a run's initial manifest.
///
/// Used in the second phase of two-phase run creation (D2.20):
/// `create_run` → `register_shards(&[InitialShardInput])`.
/// `spec` and `cursor` are call-scoped borrowed views; backends must copy
/// their bytes into owned storage before returning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialShardInput<'a> {
    /// Unique shard identifier within the run.
    pub(crate) shard: ShardId,
    /// Key range and metadata specification for this shard.
    pub(crate) spec: ShardSpecRef<'a>,
    /// Initial cursor position. Typically [`CursorUpdate::initial()`] for
    /// fresh scans; a non-initial value resumes from a prior checkpoint.
    pub(crate) cursor: CursorUpdate<'a>,
}

impl<'a> InitialShardInput<'a> {
    /// Construct one borrowed initial-shard manifest entry.
    ///
    /// Inputs are not retained; registration paths copy bytes into backend-owned
    /// storage.
    #[must_use]
    pub fn new(shard: ShardId, spec: ShardSpecRef<'a>, cursor: CursorUpdate<'a>) -> Self {
        Self {
            shard,
            spec,
            cursor,
        }
    }

    /// The shard's unique identifier within the run.
    #[must_use]
    pub fn shard(&self) -> ShardId {
        self.shard
    }

    /// The shard's key range and metadata specification.
    #[must_use]
    pub fn spec(&self) -> ShardSpecRef<'a> {
        self.spec
    }

    /// Initial cursor position for this shard. Typically
    /// [`CursorUpdate::initial()`] for fresh scans, or a resume point
    /// for partially-completed shards.
    #[must_use]
    pub fn cursor(&self) -> CursorUpdate<'a> {
        self.cursor
    }
}

// ============================================================================
// ManifestValidationError
// ============================================================================

/// Error from `validate_manifest`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestValidationError {
    /// The manifest is empty — at least one shard is required.
    Empty,
    /// Two shards have the same `ShardId`.
    DuplicateIds { shard_id: ShardId },
    /// Two shards have overlapping key ranges.
    OverlappingRanges { shard_a: ShardId, shard_b: ShardId },
    /// A shard's spec is internally invalid.
    InvalidSpec { shard_id: ShardId },
    /// Too many shards (SEC-3).
    TooManyShards { count: usize, max: usize },
    /// A non-initial cursor falls outside the shard's key range.
    CursorOutOfBounds { shard_id: ShardId },
    /// A cursor's `last_key` exceeds [`MAX_KEY_SIZE`] bytes.
    CursorKeyTooLarge {
        shard_id: ShardId,
        size: usize,
        max: usize,
    },
    /// A shard has an unbounded key range (empty start or end).
    ///
    /// Unbounded specs are test-only constructs. Production manifests must
    /// have finite, bounded key ranges so that overlap detection and shard
    /// coordination operate on well-defined intervals.
    UnboundedRange { shard_id: ShardId },
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("manifest is empty"),
            Self::DuplicateIds { shard_id } => {
                write!(f, "duplicate shard id: {:?}", shard_id)
            }
            Self::OverlappingRanges { shard_a, shard_b } => {
                write!(
                    f,
                    "overlapping ranges: shard {:?} and {:?}",
                    shard_a, shard_b,
                )
            }
            Self::InvalidSpec { shard_id } => {
                write!(f, "invalid spec for shard {:?}", shard_id)
            }
            Self::TooManyShards { count, max } => {
                write!(f, "too many shards: {count} exceeds max {max}")
            }
            Self::CursorOutOfBounds { shard_id } => {
                write!(f, "cursor out of bounds for shard {:?}", shard_id)
            }
            Self::CursorKeyTooLarge {
                shard_id,
                size,
                max,
            } => {
                write!(
                    f,
                    "cursor key too large for shard {:?}: {size} bytes exceeds max {max}",
                    shard_id,
                )
            }
            Self::UnboundedRange { shard_id } => {
                write!(f, "unbounded range for shard {:?}", shard_id)
            }
        }
    }
}

impl std::error::Error for ManifestValidationError {}

// ============================================================================
// validate_manifest
// ============================================================================

/// Validate a manifest of initial shards before registration.
///
/// This is the gatekeeper for all shard data entering the coordination
/// layer through `register_shards`. Every property that could cause
/// invariant violations downstream is checked here, before any records
/// are created.
///
/// ## Check order (fail-fast, cheapest first)
///
/// 1. **Count limit** -- `shards.len() <= MAX_INITIAL_SHARDS`. Checked
///    FIRST (before any allocation) to prevent resource exhaustion from
///    a single oversized API call.
/// 2. **Non-empty** -- at least one shard required.
/// 3. **No duplicate IDs** -- sort + adjacent-pair scan, O(N log N).
/// 4. **No unbounded ranges** -- production manifests must have finite
///    `[start, end)` intervals. Unbounded specs are test-only constructs.
/// 5. **Spec validity** -- `start < end` for bounded ranges.
/// 6. **No overlapping key ranges** -- sort by `key_range_start`, then
///    check that each `key_range_end` does not exceed the next shard's
///    `key_range_start`. Gaps between shards are allowed (sparse coverage).
/// 7. **Cursor key size** -- `last_key.len() <= MAX_KEY_SIZE` for
///    non-initial cursors. Defense-in-depth against oversized keys.
/// 8. **Cursor bounds** -- non-initial cursors must fall within
///    `[spec.start, spec.end)`.
///
/// ## Design note
///
/// Overlap detection uses sorted-adjacency comparison, not pairwise
/// comparison. This is O(N log N) (dominated by the sort) rather than
/// O(N^2), which matters at `MAX_INITIAL_SHARDS` (10K).
pub fn validate_manifest(shards: &[InitialShardInput<'_>]) -> Result<(), ManifestValidationError> {
    // SEC-3: Bound check FIRST, before any allocation.
    if shards.len() > MAX_INITIAL_SHARDS {
        return Err(ManifestValidationError::TooManyShards {
            count: shards.len(),
            max: MAX_INITIAL_SHARDS,
        });
    }

    if shards.is_empty() {
        return Err(ManifestValidationError::Empty);
    }

    let mut sorted_indices: Vec<usize> = (0..shards.len()).collect();

    // Check for duplicate IDs.
    sorted_indices.sort_by_key(|&idx| shards[idx].shard.as_raw());
    for window in sorted_indices.windows(2) {
        let current = shards[window[0]].shard;
        if current == shards[window[1]].shard {
            return Err(ManifestValidationError::DuplicateIds { shard_id: current });
        }
    }

    // Reject unbounded ranges: production manifests must have finite bounds.
    for shard in shards {
        if shard.spec.key_range_start().is_empty() || shard.spec.key_range_end().is_empty() {
            return Err(ManifestValidationError::UnboundedRange {
                shard_id: shard.shard,
            });
        }
    }

    // Validate per-spec size limits (key sizes, metadata size, range ordering).
    // ShardSpecRef is intentionally unvalidated at construction time; this is the
    // gate that prevents oversized specs from reaching AcquireScratch::write_spec,
    // which uses panicking asserts on the same size ceilings.
    for shard in shards {
        if ShardSpec::validate_ref(shard.spec).is_err() {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard,
            });
        }
    }

    // Sort by key_range_start for overlap detection.
    sorted_indices.sort_by(|&a, &b| {
        shards[a]
            .spec
            .key_range_start()
            .cmp(shards[b].spec.key_range_start())
    });

    for &index in sorted_indices.iter() {
        let shard = &shards[index];
        // Validate that start < end for bounded specs.
        let start = shard.spec.key_range_start();
        let end = shard.spec.key_range_end();
        if !start.is_empty() && !end.is_empty() && start >= end {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard,
            });
        }
    }

    // Check for overlapping ranges.
    // Ranges are sorted by key_range_start. Two adjacent sorted ranges
    // [a_start, a_end) and [b_start, b_end) overlap iff a_end > b_start.
    // The empty checks are defense-in-depth: the unbounded-range rejection
    // above guarantees all starts/ends are non-empty at this point.
    for window in sorted_indices.windows(2) {
        let a = &shards[window[0]];
        let b = &shards[window[1]];
        let a_end = a.spec.key_range_end();
        let b_start = b.spec.key_range_start();
        let overlaps = a_end.is_empty() || b_start.is_empty() || a_end > b_start;
        if overlaps {
            return Err(ManifestValidationError::OverlappingRanges {
                shard_a: a.shard,
                shard_b: b.shard,
            });
        }
    }

    // Cursor key size check (defense-in-depth; CursorUpdate::try_with_last_key
    // also validates, but callers may use the panicking constructors).
    for shard in shards {
        if let Some(key) = shard.cursor.last_key()
            && key.len() > MAX_KEY_SIZE
        {
            return Err(ManifestValidationError::CursorKeyTooLarge {
                shard_id: shard.shard,
                size: key.len(),
                max: MAX_KEY_SIZE,
            });
        }
    }

    // Cursor bounds check for non-initial cursors.
    for shard in shards {
        if let Some(key) = shard.cursor.last_key() {
            let start = shard.spec.key_range_start();
            let end = shard.spec.key_range_end();
            let in_bounds = (start.is_empty() || key >= start) && (end.is_empty() || key < end);
            if !in_bounds {
                return Err(ManifestValidationError::CursorOutOfBounds {
                    shard_id: shard.shard,
                });
            }
        }
    }

    Ok(())
}
