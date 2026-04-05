//! Shard manifest input type and validation for run registration.
//!
//! [`InitialShardInput`] is the borrowed entry type for the initial shard
//! manifest passed to `register_shards`. [`validate_manifest`] enforces
//! structural constraints (uniqueness, bounded ranges, cursor bounds) before
//! any records are created in the coordination layer.
//!
//! # Invariants
//!
//! - **Bounded Ranges:** Production manifests strictly require finite `[start, end)`
//!   intervals to guarantee overlap detection correctness.
//! - **Uniqueness:** A single run must never declare duplicate `ShardId`s.
//!
//! # Algorithms
//!
//! Validation occurs in a fail-fast order: count limits first (before allocation),
//! followed by uniqueness checks, spec validity, and finally range overlap
//! detection.
//!
//! # Design Trade-offs
//!
//! - **O(N log N) Overlap Detection:** We sort shards by start key and check
//!   adjacent pairs rather than using an interval tree. This optimizes for
//!   the common case where shards don't overlap, scaling well up to the maximum
//!   shard limits.

use crate::coordination::cursor::{CursorUpdate, MAX_KEY_SIZE};
use crate::coordination::shard_spec::{ShardSpec, ShardSpecInputError, ShardSpecRef};
use crate::identity::ShardId;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of shards in a single `register_shards` call.
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
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestValidationError {
    /// The manifest is empty — at least one shard is required.
    #[error("manifest is empty")]
    Empty,
    /// Two shards have the same `ShardId`.
    #[error("duplicate shard id: {shard_id:?}")]
    DuplicateIds { shard_id: ShardId },
    /// Two shards have overlapping key ranges.
    #[error("overlapping ranges: shard {shard_a:?} and {shard_b:?}")]
    OverlappingRanges { shard_a: ShardId, shard_b: ShardId },
    /// A shard's spec is internally invalid.
    #[error("invalid spec for shard {shard_id:?}: {reason}")]
    InvalidSpec {
        shard_id: ShardId,
        #[source]
        reason: ShardSpecInputError,
    },
    /// Too many shards.
    #[error("too many shards: {count} exceeds max {max}")]
    TooManyShards { count: usize, max: usize },
    /// A non-initial cursor falls outside the shard's key range.
    #[error("cursor out of bounds for shard {shard_id:?}")]
    CursorOutOfBounds { shard_id: ShardId },
    /// A cursor's `last_key` exceeds [`MAX_KEY_SIZE`] bytes.
    #[error("cursor key too large for shard {shard_id:?}: {size} bytes exceeds max {max}")]
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
    #[error("unbounded range for shard {shard_id:?}")]
    UnboundedRange { shard_id: ShardId },
}

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

    sorted_indices.sort_by_key(|&idx| shards[idx].shard.as_raw());
    for window in sorted_indices.windows(2) {
        let current = shards[window[0]].shard;
        if current == shards[window[1]].shard {
            return Err(ManifestValidationError::DuplicateIds { shard_id: current });
        }
    }

    for shard in shards {
        if shard.spec.key_range_start().is_empty() || shard.spec.key_range_end().is_empty() {
            return Err(ManifestValidationError::UnboundedRange {
                shard_id: shard.shard,
            });
        }
    }

    for shard in shards {
        if let Err(reason) = ShardSpec::validate_ref(shard.spec) {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard,
                reason,
            });
        }
    }

    sorted_indices.sort_by(|&a, &b| {
        shards[a]
            .spec
            .key_range_start()
            .cmp(shards[b].spec.key_range_start())
    });

    for &index in sorted_indices.iter() {
        let shard = &shards[index];
        let start = shard.spec.key_range_start();
        let end = shard.spec.key_range_end();
        if !start.is_empty() && !end.is_empty() && start >= end {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard,
                reason: ShardSpecInputError::InvertedRange {
                    start_len: start.len(),
                    end_len: end.len(),
                },
            });
        }
    }

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
