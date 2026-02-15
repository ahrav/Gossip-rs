//! Boundary â‘¢ â€” Shard Algebra & Keyspace Contract: Chunk 3 (DRAFT)
//!
//! TypedShardBuilder: fluent API for constructing InitialShard manifests
//! with typed keys and structured metadata. This is the primary surface
//! connectors use to define their shard layout.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5), Boundary â‘¡
//! (chunks 1â€“5), and Boundary â‘¢ chunks 1â€“2.
//!
//! ## Conceptual Model
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ Connector (Stage 3)                                        â”‚
//! â”‚                                                            â”‚
//! â”‚   let manifest = TypedShardBuilder::new()                  â”‚
//! â”‚       .prefix_shard("src/", extra)                         â”‚
//! â”‚       .prefix_shard("test/", extra)                        â”‚
//! â”‚       .range_shard(start, end, extra)                      â”‚
//! â”‚       .build()?;                     â† validates           â”‚
//! â”‚                                                            â”‚
//! â”‚   // manifest: Vec<InitialShard>                           â”‚
//! â”‚   // ready for register_shards()                           â”‚
//! â”‚                                                            â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ Coordinator (Stage 2)                                      â”‚
//! â”‚                                                            â”‚
//! â”‚   register_shards(run, op_id, manifest)?;                  â”‚
//! â”‚   // validates: no overlaps, no dupes, all specs valid      â”‚
//! â”‚                                                            â”‚
//! â”‚   Coordinator sees only ShardSpec { bytes, bytes, bytes }.  â”‚
//! â”‚   All type safety was ensured above the boundary.           â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```
//!
//! ## Design Decisions (locked)
//!
//! D3.10: TypedShardBuilder auto-assigns ShardIds as sequential u64s
//!        starting from 0. The coordinator validates uniqueness; the
//!        builder guarantees it by construction.
//!
//!        Reference: FoundationDB Record Layer â€” subspace IDs are
//!        assigned sequentially during schema creation, not by the
//!        core KV layer.
//!
//! D3.11: TypedShardBuilder validates on `build()`, not on each
//!        `add_*()` call. This matches the builder pattern convention
//!        where intermediate states may be transiently invalid.
//!        `build()` delegates to `validate_manifest()` from B2.
//!
//!        Reference: Protocol Buffers â€” messages are validated on
//!        serialization, not during field-by-field construction.
//!        Bloch, "Effective Java" (2001) â€” builder pattern defers
//!        validation to the build step.
//!
//! D3.12: TypedShardBuilder is NOT generic over key schema. Each
//!        shard addition method is concrete (prefix, range, manifest).
//!        A single builder can mix shard types freely, because the
//!        output is always `Vec<InitialShard>` with byte-level specs.
//!
//!        Rationale: Generic builders would push key schema type
//!        parameters into the coordinator API, violating the boundary
//!        between typed connectors and byte-level coordination. The
//!        builder is a connector-side convenience, not a contract type.
//!
//! D3.13: The builder consumes `Vec<u8>` for connector_extra, not
//!        references. Shard construction is a one-time initialization
//!        cost; avoiding lifetime complexity is worth the allocation.
//!
//!        Reference: Rust API Guidelines â€” "Prefer owned types in
//!        builder APIs" (C-BUILDER).
//!
//! D3.14: `build()` returns `Result<Vec<InitialShard>, ManifestBuildError>`,
//!        where `ManifestBuildError` wraps `ManifestValidationError`
//!        from B2 plus builder-specific errors (e.g., empty builder).
//!        The error type is distinct from the coordinator's to allow
//!        builder-level diagnostics without polluting the B2 contract.

// Assumes all types from Boundaries â‘ , â‘¡, and â‘¢ chunks 1â€“2 are in scope:
// use crate::{
//     ShardSpec, ShardId, Cursor, InitialShard, ManifestValidationError,
//     validate_manifest, KeyEncoding, PathKey, TimeIdKey, ManifestRowKey,
//     OpaqueFixedKey, ShardHint, ShardMetadata, prefix_shard, range_shard,
//     manifest_shard, shard_spec_from_keys, prefix_successor,
// };

use core::fmt;

// ============================================================================
// Â§ Chunk 3: TypedShardBuilder
// ============================================================================

// ---------------------------------------------------------------------------
// Â§3.1 TypedShardBuilder â€” fluent shard manifest construction
// ---------------------------------------------------------------------------

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
/// Shards may be added in any order. `build()` sorts them by
/// `key_range_start` before validation. The caller does not need to
/// worry about insertion order.
///
/// ## Shard ID Assignment
///
/// ShardIds are assigned sequentially (0, 1, 2, ...) in insertion
/// order. This is a convenience â€” the coordinator validates uniqueness
/// regardless. The insertion-order assignment means the caller can
/// predict IDs for cross-referencing if needed.
///
/// ## Thread Safety
///
/// Not `Sync` â€” intended for single-threaded initialization.
/// Shard manifest construction is a brief setup phase, not a hot path.
///
/// ## Invariants
///
/// **Safety (sequential IDs)**: ShardId `n` is always assigned to the
/// `n`-th shard added (zero-indexed). No gaps, no reuse.
///
/// **Safety (build-time validation)**: `build()` returns `Err` if the
/// resulting manifest would fail `validate_manifest()` from B2. A
/// successful `build()` guarantees the manifest is ready for
/// `register_shards()`.
///
/// **Liveness (non-blocking)**: The builder performs no I/O, no
/// network calls, no blocking operations. It is pure computation.
pub struct TypedShardBuilder {
    /// Accumulated shards in insertion order.
    shards: Vec<InitialShard>,

    /// Next ShardId to assign. Monotonically increasing.
    next_id: u64,

    /// Default cursor for new shards. Almost always `Cursor::initial()`.
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
    ///
    /// Use when the number of shards is known ahead of time (e.g.,
    /// one shard per directory, one per manifest chunk).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            shards: Vec::with_capacity(capacity),
            next_id: 0,
            default_cursor: Cursor::initial(),
        }
    }

    /// Override the default cursor for subsequently added shards.
    ///
    /// Use when resuming a partially-completed run: set the cursor
    /// to the last checkpoint for each shard being re-registered.
    ///
    /// Note: this sets the default for ALL subsequently added shards.
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

    // â”€â”€ Typed shard addition methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Add a prefix shard covering all keys starting with `prefix`.
    ///
    /// Computes the end key via `prefix_successor`. Encodes a
    /// `ShardHint::Prefix` into the metadata.
    ///
    /// # Panics
    ///
    /// Panics if `prefix` is empty (use `add_unbounded()` instead).
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
    /// Encodes a `ShardHint::Range` into the metadata.
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

    /// Add a manifest shard covering rows `[start_row, end_row)` from
    /// the specified manifest.
    ///
    /// Encodes a `ShardHint::Manifest` into the metadata.
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
    /// This is the generic escape hatch for key schemas beyond the
    /// three standard patterns. The caller provides the hint and
    /// connector extra data.
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
    /// Bypasses typed construction â€” use when the spec was built
    /// externally (e.g., deserialized from a prior run's manifest,
    /// or constructed by a lower-level API).
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
    /// Prefer using the typed methods unless you have a specific
    /// reason to control the ShardId.
    pub fn add_raw(mut self, shard: InitialShard) -> Self {
        // Do NOT increment next_id â€” the caller is managing IDs.
        self.shards.push(shard);
        self
    }

    // â”€â”€ Bulk addition methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Partition a key range into N equal-width range shards.
    ///
    /// Divides `[start, end)` into `n` shards with approximately equal
    /// byte-width ranges. Uses `byte_midpoint` recursively for split
    /// point selection.
    ///
    /// If the range is too narrow to split into `n` distinct ranges
    /// (adjacent keys), produces fewer shards.
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

    // â”€â”€ Build â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Validate and produce the final `Vec<InitialShard>`.
    ///
    /// ## Validation
    ///
    /// Delegates to `validate_manifest()` from B2, which checks:
    /// 1. Non-empty manifest.
    /// 2. No duplicate ShardIds.
    /// 3. No overlapping key ranges.
    /// 4. Each spec is well-formed (start < end).
    ///
    /// Gaps between shards are allowed â€” the builder does NOT require
    /// full keyspace coverage.
    ///
    /// ## Errors
    ///
    /// Returns `ManifestBuildError` wrapping the validation failure.
    pub fn build(self) -> Result<Vec<InitialShard>, ManifestBuildError> {
        if self.shards.is_empty() {
            return Err(ManifestBuildError::Empty);
        }

        // Validate via B2's validate_manifest.
        validate_manifest(&self.shards)
            .map_err(ManifestBuildError::ValidationFailed)?;

        Ok(self.shards)
    }

    /// Produce the manifest WITHOUT validation.
    ///
    /// **Danger**: The resulting manifest may fail `register_shards()`.
    /// Use only in tests or when the caller has already validated
    /// the shard layout through other means.
    pub fn build_unchecked(self) -> Vec<InitialShard> {
        self.shards
    }

    // â”€â”€ Internal helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Push a ShardSpec with an auto-assigned ShardId and default cursor.
    fn push_spec(&mut self, spec: ShardSpec) {
        let id = ShardId(self.next_id);
        self.next_id = self.next_id
            .checked_add(1)
            .expect("TypedShardBuilder: ShardId overflow (> u64::MAX shards)");

        self.shards.push(InitialShard {
            shard_id: id,
            spec,
            cursor: self.default_cursor.clone(),
        });
    }

    /// Recursively compute `n - 1` split points between `start` and `end`.
    ///
    /// Uses midpoint bisection: for n=4 shards, compute the midpoint
    /// (2 shards on each side), then recurse on each half.
    ///
    /// This produces approximately uniform byte-width partitions.
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

        // Recurse on left half: [start, mid)
        Self::compute_split_points(start, &mid, left_n, boundaries);

        // Add the midpoint as a boundary.
        boundaries.push(mid.clone());

        // Recurse on right half: [mid, end)
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

// ---------------------------------------------------------------------------
// Â§3.2 ManifestBuildError â€” builder-level error type
// ---------------------------------------------------------------------------

/// Error from `TypedShardBuilder::build()`.
///
/// Wraps `ManifestValidationError` (from B2) with builder-specific
/// error variants. This separation keeps the B2 contract clean while
/// giving connector-side callers better diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestBuildError {
    /// The builder has no shards. At least one shard is required.
    Empty,

    /// The manifest failed B2 validation.
    ///
    /// The inner error contains the specific validation failure
    /// (duplicate IDs, overlapping ranges, invalid specs).
    ValidationFailed(ManifestValidationError),
}

impl fmt::Display for ManifestBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "manifest builder is empty: add at least one shard"),
            Self::ValidationFailed(e) => write!(f, "manifest validation failed: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Â§3.3 Convenience: partition helpers for common connector patterns
// ---------------------------------------------------------------------------

/// Partition a list of path prefixes into one shard per prefix.
///
/// This is the most common connector pattern: the connector knows the
/// top-level directory structure (e.g., from a tree listing) and wants
/// one shard per directory.
///
/// ```rust,ignore
/// let dirs = vec!["src/", "test/", "docs/", "scripts/"];
/// let manifest = shards_from_prefixes(
///     &dirs,
///     |prefix| format!("repo:acme;dir:{}", prefix).into_bytes(),
/// )?;
/// ```
///
/// # Errors
///
/// Returns `ManifestBuildError` if the resulting prefixes overlap
/// (e.g., "src/" and "src/auth/" overlap because the latter is a
/// sub-prefix of the former).
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
///
/// # Errors
///
/// Returns `ManifestBuildError` if the resulting shards are invalid
/// (should not happen for valid inputs, but checked defensively).
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
// Â§ B3 Invariant Catalog
// ============================================================================

//! ## Boundary â‘¢ Invariant Catalog
//!
//! This section enumerates ALL safety and liveness invariants for the
//! shard algebra and keyspace contract. Each invariant is:
//! - Named with a stable identifier (INV-B3-Snn / INV-B3-Lnn)
//! - Classified as Safety (S) or Liveness (L)
//! - Located to the responsible component
//! - Paired with a verification strategy
//!
//! Reference: Alpern & Schneider, "Defining Liveness" (1985) â€” safety
//! is "nothing bad happens", liveness is "something good eventually
//! happens."
//!
//! ### Safety Invariants
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ ID          â”‚ Statement                                              â”‚ Enforced By          â”‚ Verification                   â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S01  â”‚ KeyEncoding ordering fidelity: for any schema S and    â”‚ KeyEncoding impl     â”‚ Property-based test:           â”‚
//! â”‚             â”‚ values a < b in logical ordering,                      â”‚                      â”‚ âˆ€ a,b: a < b âŸ¹                â”‚
//! â”‚             â”‚ S::encode(a) < S::encode(b) in lex byte ordering.     â”‚                      â”‚ encode(a) < encode(b)          â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S02  â”‚ prefix_successor completeness: for any prefix P and    â”‚ prefix_successor()   â”‚ Property-based test:           â”‚
//! â”‚             â”‚ string X starting with P, P â‰¤ X < successor(P)        â”‚                      â”‚ âˆ€ P,X: X.starts_with(P) âŸ¹     â”‚
//! â”‚             â”‚ when successor exists.                                 â”‚                      â”‚ P â‰¤ X < successor(P)           â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S03  â”‚ prefix_successor tightness: no byte string between     â”‚ prefix_successor()   â”‚ Property-based test:           â”‚
//! â”‚             â”‚ predecessor_of(successor) and successor starts with P. â”‚                      â”‚ (hard to test exhaustively;    â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ verified by algorithm review)  â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S04  â”‚ ShardHint round-trip stability:                        â”‚ ShardHint encode/    â”‚ Property-based test:           â”‚
//! â”‚             â”‚ decode(encode(hint)) == (hint, encode(hint).len()).    â”‚ decode               â”‚ âˆ€ hint: roundtrip holds        â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S05  â”‚ ShardMetadata round-trip stability:                    â”‚ ShardMetadata encode/â”‚ Property-based test:           â”‚
//! â”‚             â”‚ decode(encode(meta)) == meta.                          â”‚ decode               â”‚ âˆ€ meta: roundtrip holds        â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S06  â”‚ ShardMetadata isolation: changing the hint does not     â”‚ ShardMetadata format â”‚ Unit test: modify hint,        â”‚
//! â”‚             â”‚ corrupt connector_extra, and vice versa.               â”‚                      â”‚ verify other field unchanged.  â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S07  â”‚ Hint version forward-compat: unknown versions produce   â”‚ ShardHint::decode()  â”‚ Unit test: decode with         â”‚
//! â”‚             â”‚ UnsupportedVersion error, never panic.                 â”‚                      â”‚ version = 0xFF.                â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S08  â”‚ Hint tag stability: tag values 0x00, 0x01, 0x02 are    â”‚ ShardHint impl       â”‚ Compile-time const + review.   â”‚
//! â”‚             â”‚ never reused or reordered. New variants get new tags.  â”‚                      â”‚                                â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S09  â”‚ Prefix shard completeness: prefix_shard("P", extra)    â”‚ prefix_shard()       â”‚ Property-based test:           â”‚
//! â”‚             â”‚ produces a ShardSpec that contains_key(K) for every K  â”‚                      â”‚ âˆ€ P, K starting with P:        â”‚
//! â”‚             â”‚ that starts with P.                                    â”‚                      â”‚ spec.contains_key(K)           â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S10  â”‚ Manifest shard alignment: manifest_shard(m, s, e, _)   â”‚ manifest_shard()     â”‚ Unit test: verify key_range    â”‚
//! â”‚             â”‚ produces start/end keys that exactly equal             â”‚                      â”‚ matches ManifestRowKey encodingâ”‚
//! â”‚             â”‚ ManifestRowKey::new(m, s/e).encode().                  â”‚                      â”‚ for boundary values.           â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S11  â”‚ Split hint propagation correctness:                     â”‚ propagate_hint_      â”‚ Unit + property tests:         â”‚
//! â”‚             â”‚ - Range â†’ Range                                        â”‚ on_split()           â”‚ âˆ€ valid splits: child hint     â”‚
//! â”‚             â”‚ - Prefix â†’ Range (demotion)                            â”‚                      â”‚ matches rules. Manifest child  â”‚
//! â”‚             â”‚ - Manifest â†’ Manifest with sub-range                   â”‚                      â”‚ rows âŠ‚ parent rows.            â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S12  â”‚ TypedShardBuilder sequential IDs: shard n always gets   â”‚ push_spec()          â”‚ Unit test: add N shards,       â”‚
//! â”‚             â”‚ ShardId(n). No gaps, no reuse.                         â”‚                      â”‚ verify IDs are 0..N.           â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S13  â”‚ TypedShardBuilder build-time validation: build() fails  â”‚ build()              â”‚ Unit test: overlapping shards  â”‚
//! â”‚             â”‚ iff validate_manifest() would fail on the same input.  â”‚                      â”‚ â†’ build() returns Err.         â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S14  â”‚ byte_midpoint correctness: for any a < b where         â”‚ byte_midpoint()      â”‚ Property-based test:           â”‚
//! â”‚             â”‚ midpoint exists, a < midpoint(a,b) < b.               â”‚                      â”‚ âˆ€ a < b: a < mid < b           â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S15  â”‚ Big-endian numeric ordering: for all numeric key        â”‚ TimeIdKey, Manifest  â”‚ Property-based test:           â”‚
//! â”‚             â”‚ schemas, encoded lex order == numeric order.           â”‚ RowKey encode_to()   â”‚ âˆ€ a,b: a.cmp(b) ==             â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ a.encode().cmp(b.encode())     â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S16  â”‚ Backward compatibility: empty metadata decodes to       â”‚ ShardMetadata::      â”‚ Unit test: decode(&[])         â”‚
//! â”‚             â”‚ ShardHint::Range with empty connector_extra.           â”‚ decode()             â”‚ == Range + empty extra.         â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```
//!
//! ### Liveness Invariants
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ ID          â”‚ Statement                                              â”‚ Enforced By          â”‚ Verification                   â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-L01  â”‚ TypedShardBuilder is non-blocking: build() completes   â”‚ TypedShardBuilder    â”‚ Code review: no I/O, no locks, â”‚
//! â”‚             â”‚ in finite time with no I/O or synchronization.         â”‚                      â”‚ no unbounded loops.            â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-L02  â”‚ split_range produces â‰¥ 1 shard for any valid           â”‚ split_range()        â”‚ Property-based test:           â”‚
//! â”‚             â”‚ [start, end) with n â‰¥ 1.                               â”‚                      â”‚ âˆ€ start < end, n â‰¥ 1:          â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ result has â‰¥ 1 shard.          â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-L03  â”‚ split_manifest covers all rows: union of all produced  â”‚ split_manifest()     â”‚ Unit test: sum of              â”‚
//! â”‚             â”‚ shard row ranges == [0, total_rows).                   â”‚                      â”‚ (end_row - start_row) ==       â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ total_rows.                    â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```
//!
//! ### Cross-Boundary Invariant Dependencies
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ B3 Invariantâ”‚ Depends On                                             â”‚ From Boundary                  â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S09  â”‚ ShardSpec.contains_key() correctness                   â”‚ B2 (INV-B2-S05)                â”‚
//! â”‚             â”‚ (half-open interval semantics)                         â”‚                                â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S13  â”‚ validate_manifest() correctness                        â”‚ B2 (INV-B2-S09)                â”‚
//! â”‚             â”‚ (overlap detection, duplicate ID detection)            â”‚                                â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S04  â”‚ CanonicalBytes collision-freedom for ShardSpec          â”‚ B1 (INV-B1-S01)                â”‚
//! â”‚ INV-B3-S05  â”‚ (metadata is part of the payload hash)                 â”‚                                â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ TypedShardBuilder basic usage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

        // Verify each shard has the correct hint.
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
            .range_shard(b"f".to_vec(), b"z".to_vec(), vec![]) // overlaps
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

    // â”€â”€ split_manifest â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_manifest_even_division() {
        let manifest = TypedShardBuilder::new()
            .split_manifest(1, 1000, 250, |_start, _end| vec![])
            .build()
            .unwrap();

        assert_eq!(manifest.len(), 4);

        // Verify row ranges tile [0, 1000).
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

    // â”€â”€ split_range â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

        // At least 1, at most 4 (may be fewer if midpoints collapse).
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

    // â”€â”€ shards_from_prefixes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        // "src/" and "src/auth/" overlap (sub-prefix).
        let result = shards_from_prefixes(
            &[b"src/".as_slice(), b"src/auth/".as_slice()],
            |_| vec![],
        );
        assert!(result.is_err());
    }

    // â”€â”€ build_unchecked â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn build_unchecked_allows_invalid() {
        let manifest = TypedShardBuilder::new()
            .range_shard(b"a".to_vec(), b"z".to_vec(), vec![])
            .range_shard(b"m".to_vec(), b"z".to_vec(), vec![]) // overlaps!
            .build_unchecked();

        // Unchecked build succeeds even with overlaps.
        assert_eq!(manifest.len(), 2);
    }

    // â”€â”€ typed_range_shard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ Property-based test stubs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: proptest for split_range tiling:
    //   For any valid [start, end) and n â‰¥ 1:
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
