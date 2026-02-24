//! TypedShardBuilder: fluent API for constructing InitialShard manifests
//! with typed keys and structured metadata.
//!
//! This is the primary surface connectors use to define their shard layout.
//! The builder validates the manifest on `build()`, not on each addition,
//! matching the standard builder pattern convention.
//!
//! ## Design Decisions (locked)
//!
//! D3.10: Auto-assigns ShardIds as sequential u64s starting from 0.
//!        The coordinator validates uniqueness; the builder guarantees
//!        it by construction.
//!
//! D3.11: Validates on `build()`, not on each `add_*()` call.
//!        Reference: Protocol Buffers, Bloch "Effective Java" builder.
//!
//! D3.12: NOT generic over key schema. Each addition method is concrete.
//!        A single builder can mix shard types freely.
//!
//! D3.13: Consumes `Vec<u8>` for connector_extra (owned types in builders).
//!        Reference: Rust API Guidelines C-BUILDER.
//!
//! D3.14: `build()` returns `Result<Vec<InitialShard>, ManifestBuildError>`.

use core::fmt;

use crate::identity::ShardId;
use crate::coordination::cursor::Cursor;
use crate::coordination::shard_spec::{
    InitialShard,
    ManifestValidationError,
    ShardSpec,
    validate_manifest,
};

use super::hint::{
    ShardHint,
    ShardMetadata,
    range_shard,
    prefix_shard,
    manifest_shard,
};
use super::key_encoding::{
    KeyEncoding,
    byte_midpoint,
    shard_spec_from_keys,
};

// ============================================================================
// § TypedShardBuilder
// ============================================================================

/// Fluent builder for constructing a validated `Vec<InitialShard>` manifest.
///
/// ## Usage
///
/// ```rust,ignore
/// let manifest = TypedShardBuilder::new()
///     .prefix_shard(b"src/".to_vec(), vec![])
///     .prefix_shard(b"test/".to_vec(), vec![])
///     .manifest_shard(1, 0, 5000, vec![])
///     .build()?;
///
/// coordinator.register_shards(run_id, op_id, manifest)?;
/// ```
///
/// ## Ordering
///
/// Shards may be added in any order. `build()` delegates to
/// `validate_manifest()` which sorts internally.
///
/// ## Shard ID Assignment
///
/// ShardIds are assigned sequentially (0, 1, 2, ...) in insertion
/// order. The coordinator validates uniqueness regardless.
///
/// ## Invariants
///
/// **Safety (sequential IDs)**: ShardId `n` is always assigned to the
/// `n`-th shard added (zero-indexed). No gaps, no reuse.
///
/// **Safety (build-time validation)**: `build()` returns `Err` if the
/// resulting manifest would fail `validate_manifest()`.
///
/// **Liveness (non-blocking)**: The builder performs no I/O, no
/// network calls, no blocking operations. It is pure computation.
pub struct TypedShardBuilder {
    /// Accumulated shards in insertion order.
    shards: Vec<InitialShard>,

    /// Next ShardId to assign. Monotonically increasing.
    next_id: u64,

    /// Default cursor for new shards.
    default_cursor: Cursor,
}

impl TypedShardBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            shards: Vec::new(),
            next_id: 0,
            default_cursor: Cursor::initial(),
        }
    }

    /// Create a builder with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            shards: Vec::with_capacity(capacity),
            next_id: 0,
            default_cursor: Cursor::initial(),
        }
    }

    /// Override the default cursor for subsequently added shards.
    ///
    /// Use when resuming a partially-completed run.
    /// For per-shard cursors, use `add_raw()`.
    pub fn with_default_cursor(mut self, cursor: Cursor) -> Self {
        self.default_cursor = cursor;
        self
    }

    /// The number of shards added so far.
    #[inline]
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    /// Returns `true` if no shards have been added.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    // ── Typed shard addition methods ────────────────────────────────────

    /// Add a prefix shard covering all keys starting with `prefix`.
    ///
    /// # Panics
    ///
    /// Panics if `prefix` is empty.
    pub fn prefix_shard(
        mut self,
        prefix: Vec<u8>,
        connector_extra: Vec<u8>,
    ) -> Self {
        let spec = prefix_shard(prefix, connector_extra);
        self.push_spec(spec);
        self
    }

    /// Add a generic range shard covering `[start, end)`.
    ///
    /// # Panics
    ///
    /// Panics if `start >= end` when both are non-empty.
    pub fn range_shard(
        mut self,
        start: Vec<u8>,
        end: Vec<u8>,
        connector_extra: Vec<u8>,
    ) -> Self {
        let spec = range_shard(start, end, connector_extra);
        self.push_spec(spec);
        self
    }

    /// Add a manifest shard covering rows `[start_row, end_row)`.
    ///
    /// # Panics
    ///
    /// Panics if `start_row >= end_row`.
    pub fn manifest_shard(
        mut self,
        manifest_id: u64,
        start_row: u64,
        end_row: u64,
        connector_extra: Vec<u8>,
    ) -> Self {
        let spec = manifest_shard(manifest_id, start_row, end_row, connector_extra);
        self.push_spec(spec);
        self
    }

    /// Add a typed range shard using any `KeyEncoding` implementor.
    ///
    /// Generic escape hatch for key schemas beyond the three standard
    /// patterns. The caller provides the hint and connector extra data.
    ///
    /// # Panics
    ///
    /// Panics if the encoded start >= encoded end.
    pub fn typed_range_shard<K: KeyEncoding>(
        mut self,
        start: &K,
        end: &K,
        hint: ShardHint,
        connector_extra: Vec<u8>,
    ) -> Self {
        let metadata = ShardMetadata::new(hint, connector_extra);
        let spec = shard_spec_from_keys(start, end, metadata.encode());
        self.push_spec(spec);
        self
    }

    /// Add a pre-built `ShardSpec` directly.
    ///
    /// Bypasses typed construction — use when the spec was built
    /// externally or deserialized from a prior run's manifest.
    pub fn add_raw_spec(mut self, spec: ShardSpec) -> Self {
        self.push_spec(spec);
        self
    }

    /// Add a pre-built `InitialShard` directly, including a custom
    /// shard ID and cursor.
    ///
    /// **Warning**: The caller-provided ShardId is used as-is. The
    /// builder's sequential counter is NOT updated. This can cause
    /// ID collisions if mixed with the typed addition methods.
    pub fn add_raw(mut self, shard: InitialShard) -> Self {
        self.shards.push(shard);
        self
    }

    // ── Bulk addition methods ──────────────────────────────────────────

    /// Partition a key range into N equal-width range shards.
    ///
    /// Divides `[start, end)` into `n` shards with approximately equal
    /// byte-width ranges. Uses `byte_midpoint` recursively for split
    /// point selection.
    ///
    /// If the range is too narrow to split into `n` distinct ranges,
    /// produces fewer shards.
    ///
    /// All produced shards have `ShardHint::Range`.
    ///
    /// # Panics
    ///
    /// Panics if `n == 0` or `start >= end`.
    pub fn split_range(
        mut self,
        start: Vec<u8>,
        end: Vec<u8>,
        n: usize,
        connector_extra_fn: impl Fn(usize) -> Vec<u8>,
    ) -> Self {
        assert!(n > 0, "split_range: n must be > 0");
        assert!(
            start.as_slice() < end.as_slice(),
            "split_range: start must be < end"
        );

        // Compute split points by recursive midpoint bisection.
        let mut boundaries = vec![start.clone()];
        Self::compute_split_points(&start, &end, n, &mut boundaries);
        boundaries.push(end.clone());

        // Deduplicate adjacent equal boundaries (narrow ranges).
        boundaries.dedup();

        // Produce shards from consecutive boundary pairs.
        let actual_n = boundaries.len() - 1;
        for i in 0..actual_n {
            let shard_start = boundaries[i].clone();
            let shard_end = boundaries[i + 1].clone();
            let extra = connector_extra_fn(i);

            let metadata = ShardMetadata::new(ShardHint::Range, extra);
            let spec = ShardSpec::with_range_and_metadata(
                shard_start,
                shard_end,
                metadata.encode(),
            );
            self.push_spec(spec);
        }

        self
    }

    /// Partition a manifest into fixed-size row chunks.
    ///
    /// Divides manifest `manifest_id` rows `[0, total_rows)` into
    /// shards of `chunk_size` rows each. The last shard may be smaller.
    ///
    /// # Panics
    ///
    /// Panics if `total_rows == 0` or `chunk_size == 0`.
    pub fn split_manifest(
        mut self,
        manifest_id: u64,
        total_rows: u64,
        chunk_size: u64,
        connector_extra_fn: impl Fn(u64, u64) -> Vec<u8>,
    ) -> Self {
        assert!(total_rows > 0, "split_manifest: total_rows must be > 0");
        assert!(chunk_size > 0, "split_manifest: chunk_size must be > 0");

        let mut row = 0u64;
        while row < total_rows {
            let end_row = core::cmp::min(row + chunk_size, total_rows);
            let extra = connector_extra_fn(row, end_row);
            let spec = manifest_shard(manifest_id, row, end_row, extra);
            self.push_spec(spec);
            row = end_row;
        }

        self
    }

    // ── Build ──────────────────────────────────────────────────────────

    /// Validate and produce the final `Vec<InitialShard>`.
    ///
    /// Delegates to `validate_manifest()` from B2, which checks:
    /// 1. Non-empty manifest.
    /// 2. No duplicate ShardIds.
    /// 3. No overlapping key ranges.
    /// 4. Each spec is well-formed (start < end).
    ///
    /// Gaps between shards are allowed.
    pub fn build(self) -> Result<Vec<InitialShard>, ManifestBuildError> {
        if self.shards.is_empty() {
            return Err(ManifestBuildError::Empty);
        }

        validate_manifest(&self.shards)
            .map_err(ManifestBuildError::ValidationFailed)?;

        Ok(self.shards)
    }

    /// Produce the manifest WITHOUT validation.
    ///
    /// **Danger**: The resulting manifest may fail `register_shards()`.
    /// Use only in tests or when the caller has already validated.
    pub fn build_unchecked(self) -> Vec<InitialShard> {
        self.shards
    }

    // ── Internal helpers ───────────────────────────────────────────────

    /// Push a ShardSpec with an auto-assigned ShardId and default cursor.
    fn push_spec(&mut self, spec: ShardSpec) {
        let id = ShardId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("TypedShardBuilder: ShardId overflow (> u64::MAX shards)");

        self.shards.push(InitialShard {
            shard_id: id,
            spec,
            cursor: self.default_cursor.clone(),
        });
    }

    /// Recursively compute `n - 1` split points between `start` and `end`.
    fn compute_split_points(
        start: &[u8],
        end: &[u8],
        n: usize,
        boundaries: &mut Vec<Vec<u8>>,
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

        Self::compute_split_points(start, &mid, left_n, boundaries);
        boundaries.push(mid.clone());
        Self::compute_split_points(&mid, end, right_n, boundaries);
    }
}

impl Default for TypedShardBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TypedShardBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedShardBuilder")
            .field("shard_count", &self.shards.len())
            .field("next_id", &self.next_id)
            .finish()
    }
}

// ============================================================================
// § ManifestBuildError
// ============================================================================

/// Error from `TypedShardBuilder::build()`.
///
/// Wraps `ManifestValidationError` (from B2) with builder-specific
/// error variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestBuildError {
    /// The builder has no shards.
    Empty,

    /// The manifest failed B2 validation.
    ValidationFailed(ManifestValidationError),
}

impl fmt::Display for ManifestBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "manifest builder is empty: add at least one shard"
            ),
            Self::ValidationFailed(e) => {
                write!(f, "manifest validation failed: {}", e)
            }
        }
    }
}

// ============================================================================
// § Convenience partition helpers
// ============================================================================

/// Partition a list of path prefixes into one shard per prefix.
///
/// This is the most common connector pattern: the connector knows the
/// top-level directory structure and wants one shard per directory.
///
/// # Errors
///
/// Returns `ManifestBuildError` if the resulting prefixes overlap
/// (e.g., "src/" and "src/auth/" overlap as the latter is a sub-prefix).
pub fn shards_from_prefixes(
    prefixes: &[&[u8]],
    connector_extra_fn: impl Fn(&[u8]) -> Vec<u8>,
) -> Result<Vec<InitialShard>, ManifestBuildError> {
    let mut builder = TypedShardBuilder::with_capacity(prefixes.len());
    for prefix in prefixes {
        let extra = connector_extra_fn(prefix);
        builder = builder.prefix_shard(prefix.to_vec(), extra);
    }
    builder.build()
}

/// Partition a manifest into uniform chunks.
///
/// Convenience wrapper around `TypedShardBuilder::split_manifest`.
pub fn shards_from_manifest_chunks(
    manifest_id: u64,
    total_rows: u64,
    chunk_size: u64,
    connector_extra_fn: impl Fn(u64, u64) -> Vec<u8>,
) -> Result<Vec<InitialShard>, ManifestBuildError> {
    TypedShardBuilder::new()
        .split_manifest(manifest_id, total_rows, chunk_size, connector_extra_fn)
        .build()
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard::key_encoding::{ManifestRowKey, TimeIdKey};

    // ── TypedShardBuilder basic usage ──────────────────────────────────

    #[test]
    fn builder_empty_fails() {
        let result = TypedShardBuilder::new().build();
        assert_eq!(result, Err(ManifestBuildError::Empty));
    }

    #[test]
    fn builder_single_prefix_shard() {
        let manifest = TypedShardBuilder::new()
            .prefix_shard(b"src/".to_vec(), vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].shard_id, ShardId(0));
        assert_eq!(manifest[0].spec.key_range_start.as_ref(), b"src/");
        assert_eq!(manifest[0].spec.key_range_end.as_ref(), b"src0");
        assert!(manifest[0].cursor.is_initial());
    }

    #[test]
    fn builder_sequential_ids() {
        let manifest = TypedShardBuilder::new()
            .prefix_shard(b"a/".to_vec(), vec![])
            .prefix_shard(b"b/".to_vec(), vec![])
            .prefix_shard(b"c/".to_vec(), vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 3);
        assert_eq!(manifest[0].shard_id, ShardId(0));
        assert_eq!(manifest[1].shard_id, ShardId(1));
        assert_eq!(manifest[2].shard_id, ShardId(2));
    }

    #[test]
    fn builder_mixed_shard_types() {
        let manifest = TypedShardBuilder::new()
            .prefix_shard(b"data/".to_vec(), vec![])
            .manifest_shard(1, 0, 1000, vec![])
            .range_shard(b"\xf0".to_vec(), b"\xff".to_vec(), vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 3);

        let h0 = manifest[0].spec.decode_hint().unwrap();
        assert!(h0.is_prefix());

        let h1 = manifest[1].spec.decode_hint().unwrap();
        assert!(h1.is_manifest());

        let h2 = manifest[2].spec.decode_hint().unwrap();
        assert!(h2.is_range());
    }

    #[test]
    fn builder_overlapping_shards_rejected() {
        let result = TypedShardBuilder::new()
            .range_shard(b"a".to_vec(), b"m".to_vec(), vec![])
            .range_shard(b"f".to_vec(), b"z".to_vec(), vec![])
            .build();

        assert!(matches!(
            result,
            Err(ManifestBuildError::ValidationFailed(
                ManifestValidationError::OverlappingRanges { .. }
            ))
        ));
    }

    #[test]
    fn builder_with_connector_extra() {
        let manifest = TypedShardBuilder::new()
            .prefix_shard(
                b"src/".to_vec(),
                b"repo:acme;branch:main".to_vec(),
            )
            .build()
            .unwrap();

        let meta = manifest[0].spec.decode_metadata().unwrap();
        assert_eq!(
            meta.connector_extra.as_ref(),
            b"repo:acme;branch:main",
        );
    }

    #[test]
    fn builder_len_and_is_empty() {
        let b = TypedShardBuilder::new();
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);

        let b = b.prefix_shard(b"a/".to_vec(), vec![]);
        assert!(!b.is_empty());
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn builder_with_capacity() {
        let b = TypedShardBuilder::with_capacity(100);
        assert!(b.is_empty());
    }

    #[test]
    fn builder_default_trait() {
        let b = TypedShardBuilder::default();
        assert!(b.is_empty());
    }

    #[test]
    fn builder_debug_format() {
        let b = TypedShardBuilder::new()
            .prefix_shard(b"a/".to_vec(), vec![])
            .prefix_shard(b"b/".to_vec(), vec![]);
        let debug = format!("{:?}", b);
        assert!(debug.contains("shard_count: 2"));
        assert!(debug.contains("next_id: 2"));
    }

    #[test]
    fn builder_gaps_allowed() {
        // Non-adjacent ranges are fine — gaps are allowed.
        let manifest = TypedShardBuilder::new()
            .range_shard(b"a".to_vec(), b"c".to_vec(), vec![])
            .range_shard(b"m".to_vec(), b"p".to_vec(), vec![])
            .range_shard(b"x".to_vec(), b"z".to_vec(), vec![])
            .build()
            .unwrap();
        assert_eq!(manifest.len(), 3);
    }

    // ── add_raw_spec ───────────────────────────────────────────────────

    #[test]
    fn builder_add_raw_spec() {
        let spec = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let manifest = TypedShardBuilder::new()
            .add_raw_spec(spec)
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].shard_id, ShardId(0));
    }

    // ── add_raw ────────────────────────────────────────────────────────

    #[test]
    fn builder_add_raw_preserves_custom_id() {
        let custom_shard = InitialShard {
            shard_id: ShardId(999),
            spec: ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
            cursor: Cursor::initial(),
        };
        let manifest = TypedShardBuilder::new()
            .add_raw(custom_shard)
            .build()
            .unwrap();

        assert_eq!(manifest[0].shard_id, ShardId(999));
    }

    // ── with_default_cursor ────────────────────────────────────────────

    #[test]
    fn builder_custom_default_cursor() {
        let cursor = Cursor::with_last_key(b"checkpoint-42".to_vec());
        let manifest = TypedShardBuilder::new()
            .with_default_cursor(cursor.clone())
            .prefix_shard(b"src/".to_vec(), vec![])
            .build()
            .unwrap();

        assert_eq!(manifest[0].cursor, cursor);
        assert!(!manifest[0].cursor.is_initial());
    }

    // ── split_manifest ─────────────────────────────────────────────────

    #[test]
    fn split_manifest_even_division() {
        let manifest = TypedShardBuilder::new()
            .split_manifest(1, 1000, 250, |_start, _end| vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 4);

        let hints: Vec<_> = manifest
            .iter()
            .map(|s| s.spec.decode_hint().unwrap().manifest_fields().unwrap())
            .collect();

        assert_eq!(hints[0], (1, 0, 250));
        assert_eq!(hints[1], (1, 250, 500));
        assert_eq!(hints[2], (1, 500, 750));
        assert_eq!(hints[3], (1, 750, 1000));
    }

    #[test]
    fn split_manifest_uneven_last_chunk() {
        let manifest = TypedShardBuilder::new()
            .split_manifest(1, 1000, 300, |_start, _end| vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 4); // 300 + 300 + 300 + 100

        let last = manifest[3]
            .spec
            .decode_hint()
            .unwrap()
            .manifest_fields()
            .unwrap();
        assert_eq!(last, (1, 900, 1000));
    }

    #[test]
    fn split_manifest_single_chunk() {
        let manifest = TypedShardBuilder::new()
            .split_manifest(1, 100, 1000, |_s, _e| vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 1);
        let fields = manifest[0]
            .spec
            .decode_hint()
            .unwrap()
            .manifest_fields()
            .unwrap();
        assert_eq!(fields, (1, 0, 100));
    }

    #[test]
    fn split_manifest_row_coverage_complete() {
        let total = 997u64;
        let chunk = 100u64;
        let manifest = TypedShardBuilder::new()
            .split_manifest(1, total, chunk, |_s, _e| vec![])
            .build()
            .unwrap();

        let total_covered: u64 = manifest
            .iter()
            .map(|s| {
                let (_, start, end) = s
                    .spec
                    .decode_hint()
                    .unwrap()
                    .manifest_fields()
                    .unwrap();
                end - start
            })
            .sum();
        assert_eq!(total_covered, total);
    }

    #[test]
    fn split_manifest_connector_extra_fn_called() {
        let manifest = TypedShardBuilder::new()
            .split_manifest(1, 100, 50, |start, end| {
                format!("rows:{}-{}", start, end).into_bytes()
            })
            .build()
            .unwrap();

        let extra0 = manifest[0].spec.decode_connector_extra().unwrap();
        assert_eq!(extra0.as_ref(), b"rows:0-50");

        let extra1 = manifest[1].spec.decode_connector_extra().unwrap();
        assert_eq!(extra1.as_ref(), b"rows:50-100");
    }

    // ── split_range ────────────────────────────────────────────────────

    #[test]
    fn split_range_produces_non_overlapping_shards() {
        let manifest = TypedShardBuilder::new()
            .split_range(
                b"\x00".to_vec(),
                b"\xff".to_vec(),
                4,
                |_| vec![],
            )
            .build()
            .unwrap();

        assert!(!manifest.is_empty());
        assert!(manifest.len() <= 4);

        // Verify non-overlapping: each shard's end == next shard's start.
        for window in manifest.windows(2) {
            assert_eq!(
                window[0].spec.key_range_end,
                window[1].spec.key_range_start,
                "gap or overlap between consecutive shards"
            );
        }
    }

    #[test]
    fn split_range_covers_full_range() {
        let start = b"\x10".to_vec();
        let end = b"\xf0".to_vec();
        let manifest = TypedShardBuilder::new()
            .split_range(start.clone(), end.clone(), 4, |_| vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.first().unwrap().spec.key_range_start.as_ref(), &start[..]);
        assert_eq!(manifest.last().unwrap().spec.key_range_end.as_ref(), &end[..]);
    }

    #[test]
    fn split_range_single_shard() {
        let manifest = TypedShardBuilder::new()
            .split_range(b"a".to_vec(), b"z".to_vec(), 1, |_| vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[0].spec.key_range_start.as_ref(), b"a");
        assert_eq!(manifest[0].spec.key_range_end.as_ref(), b"z");
    }

    #[test]
    fn split_range_all_hints_are_range() {
        let manifest = TypedShardBuilder::new()
            .split_range(b"\x00".to_vec(), b"\xff".to_vec(), 3, |_| vec![])
            .build()
            .unwrap();

        for shard in &manifest {
            assert!(shard.spec.decode_hint().unwrap().is_range());
        }
    }

    #[test]
    fn split_range_connector_extra_fn_called() {
        let manifest = TypedShardBuilder::new()
            .split_range(b"\x00".to_vec(), b"\xff".to_vec(), 2, |i| {
                format!("part:{}", i).into_bytes()
            })
            .build()
            .unwrap();

        let extra0 = manifest[0].spec.decode_connector_extra().unwrap();
        assert_eq!(extra0.as_ref(), b"part:0");
    }

    #[test]
    #[should_panic(expected = "n must be > 0")]
    fn split_range_zero_n_panics() {
        TypedShardBuilder::new().split_range(
            b"a".to_vec(),
            b"z".to_vec(),
            0,
            |_| vec![],
        );
    }

    #[test]
    #[should_panic(expected = "start must be < end")]
    fn split_range_inverted_panics() {
        TypedShardBuilder::new().split_range(
            b"z".to_vec(),
            b"a".to_vec(),
            2,
            |_| vec![],
        );
    }

    // ── shards_from_prefixes ───────────────────────────────────────────

    #[test]
    fn shards_from_prefixes_basic() {
        let manifest = shards_from_prefixes(
            &[b"docs/".as_slice(), b"src/".as_slice(), b"test/".as_slice()],
            |_prefix| vec![],
        )
        .unwrap();

        assert_eq!(manifest.len(), 3);
    }

    #[test]
    fn shards_from_prefixes_overlapping_rejected() {
        let result = shards_from_prefixes(
            &[b"src/".as_slice(), b"src/auth/".as_slice()],
            |_| vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn shards_from_prefixes_with_extra() {
        let manifest = shards_from_prefixes(
            &[b"a/".as_slice(), b"b/".as_slice()],
            |prefix| format!("dir:{}", String::from_utf8_lossy(prefix)).into_bytes(),
        )
        .unwrap();

        let extra0 = manifest[0].spec.decode_connector_extra().unwrap();
        assert_eq!(extra0.as_ref(), b"dir:a/");
    }

    // ── shards_from_manifest_chunks ────────────────────────────────────

    #[test]
    fn shards_from_manifest_chunks_basic() {
        let manifest = shards_from_manifest_chunks(
            1,
            1000,
            250,
            |_start, _end| vec![],
        )
        .unwrap();
        assert_eq!(manifest.len(), 4);
    }

    // ── build_unchecked ────────────────────────────────────────────────

    #[test]
    fn build_unchecked_allows_invalid() {
        let manifest = TypedShardBuilder::new()
            .range_shard(b"a".to_vec(), b"z".to_vec(), vec![])
            .range_shard(b"m".to_vec(), b"z".to_vec(), vec![])
            .build_unchecked();

        assert_eq!(manifest.len(), 2);
    }

    // ── typed_range_shard ──────────────────────────────────────────────

    #[test]
    fn typed_range_shard_with_time_id_key() {
        let start = TimeIdKey::timestamp_only(0);
        let end = TimeIdKey::timestamp_only(1_000_000);

        let manifest = TypedShardBuilder::new()
            .typed_range_shard(
                &start,
                &end,
                ShardHint::Range,
                b"audit-log".to_vec(),
            )
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 1);
        assert_eq!(
            manifest[0].spec.key_range_start.as_ref(),
            start.encode().as_slice(),
        );
    }

    #[test]
    fn typed_range_shard_with_manifest_row_key() {
        let start = ManifestRowKey::new(5, 0);
        let end = ManifestRowKey::new(5, 100);

        let manifest = TypedShardBuilder::new()
            .typed_range_shard(
                &start,
                &end,
                ShardHint::Manifest {
                    manifest_id: 5,
                    start_row: 0,
                    end_row: 100,
                },
                vec![],
            )
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 1);
        let hint = manifest[0].spec.decode_hint().unwrap();
        assert_eq!(hint.manifest_fields().unwrap(), (5, 0, 100));
    }

    // ── ManifestBuildError Display ─────────────────────────────────────

    #[test]
    fn manifest_build_error_display() {
        let e = ManifestBuildError::Empty;
        assert!(format!("{}", e).contains("empty"));

        let e = ManifestBuildError::ValidationFailed(
            ManifestValidationError::Empty,
        );
        assert!(format!("{}", e).contains("validation failed"));
    }

    // ── End-to-end: builder → register_shards readiness ────────────────

    #[test]
    fn end_to_end_github_connector_pattern() {
        // Simulate a GitHub connector listing top-level directories.
        let dirs = vec!["src/", "test/", "docs/", "scripts/", ".github/"];
        let manifest = shards_from_prefixes(
            &dirs
                .iter()
                .map(|d| d.as_bytes() as &[u8])
                .collect::<Vec<_>>(),
            |prefix| {
                format!("repo:acme/widget;dir:{}", String::from_utf8_lossy(prefix))
                    .into_bytes()
            },
        )
        .unwrap();

        assert_eq!(manifest.len(), 5);

        // Verify all IDs are unique and sequential.
        for (i, shard) in manifest.iter().enumerate() {
            assert_eq!(shard.shard_id, ShardId(i as u64));
        }

        // Verify all hints are Prefix.
        for shard in &manifest {
            assert!(shard.spec.decode_hint().unwrap().is_prefix());
        }
    }

    #[test]
    fn end_to_end_s3_manifest_pattern() {
        // Simulate an S3 connector with a pre-built manifest of 10k objects.
        let manifest = TypedShardBuilder::new()
            .split_manifest(42, 10_000, 500, |start, end| {
                format!("s3://bucket/manifest-42.csv;rows:{}-{}", start, end)
                    .into_bytes()
            })
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 20); // 10000 / 500

        // Verify complete coverage.
        let total: u64 = manifest
            .iter()
            .map(|s| {
                let (_, s, e) = s
                    .spec
                    .decode_hint()
                    .unwrap()
                    .manifest_fields()
                    .unwrap();
                e - s
            })
            .sum();
        assert_eq!(total, 10_000);
    }

    // ── Property-based test stubs ──────────────────────────────────────

    // TODO: proptest for split_range tiling:
    //   For any valid [start, end) and n >= 1:
    //     union of shard ranges == [start, end)
    //     no gaps, no overlaps
    //
    // TODO: proptest for split_manifest coverage:
    //   For any total_rows > 0 and chunk_size > 0:
    //     sum of (end_row - start_row) across shards == total_rows
    //
    // TODO: proptest for TypedShardBuilder ID assignment:
    //   For any sequence of N additions:
    //     shard IDs == [0, 1, 2, ..., N-1]
    //
    // TODO: proptest for shards_from_prefixes:
    //   For any set of non-overlapping prefixes:
    //     build() succeeds AND each shard's hint is Prefix
}
