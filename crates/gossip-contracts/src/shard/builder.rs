//! Startup-preallocated shard builder with borrowed-first add paths.
//!
//! The builder borrows a caller-provided [`ShardArena`] and tracks entries in a
//! bounded [`InlineVec`], exposing allocation-silent add operations after
//! startup preallocation. Arena slot/byte sizing is the caller's responsibility;
//! the builder only validates logical entry limits.
//!
//! Two-phase workflow:
//! - `add_*` methods validate and stage shard specs plus optional borrowed
//!   cursor updates.
//! - [`PreallocShardBuilder::build_inputs`] materializes
//!   [`InitialShardInput`] rows and re-checks manifest-level invariants before
//!   handoff to run registration.
//!
//! Error reporting is intentionally split by phase:
//! - add-time errors isolate entry-limit violations, arena capacity failures,
//!   and rejection of invalid external handles passed to
//!   [`PreallocShardBuilder::add_spec_handle`].
//! - build-time errors surface manifest-shape violations and defensively report
//!   invalid staged handles if they are observed.

use core::fmt;

use gossip_stdx::{InlineVec, SlabFull};

use crate::coordination::{
    CursorUpdate, InitialShardInput, MAX_INITIAL_SHARDS, ManifestValidationError, ShardArena,
    ShardSpec, ShardSpecHandle, ShardSpecInputError, ShardSpecRef, validate_manifest,
};
use crate::identity::ShardId;
use crate::shard::hint::{
    ShardSpecScratch, manifest_shard_into, prefix_shard_into, range_shard_into, range_shard_ref,
};
use crate::shard::key_encoding::{ManifestRowKey, PrefixShardError, ShardIntoError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BuilderEntry<'a> {
    shard: ShardId,
    spec_handle: ShardSpecHandle,
    cursor: CursorUpdate<'a>,
}

/// Error for [`PreallocShardBuilder`] construction and add/build operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreallocShardBuilderError {
    // -- Configuration (returned from `new`) --
    /// `entry_limit` was zero.
    EntryLimitZero,
    /// `entry_limit` exceeded const generic `CAP`.
    CapMismatch { entry_limit: usize, cap: usize },
    /// `entry_limit` exceeded [`MAX_INITIAL_SHARDS`].
    EntryLimitExceedsManifestMax { entry_limit: usize, max: usize },

    // -- Add/build --
    /// Requested append would exceed configured entry budget.
    CapacityExceeded {
        limit: usize,
        current: usize,
        additional: usize,
    },
    /// Arena handle table or byte slab could not allocate another spec.
    SlabFull(SlabFull),
    /// Range constructor rejected bounds or metadata sizing.
    RangeInvalid(ShardSpecInputError),
    /// Prefix constructor rejected prefix semantics or derived range.
    PrefixInvalid(PrefixShardError),
    /// Manifest constructor rejected row bounds or metadata sizing.
    ManifestCtorInvalid(ShardSpecInputError),
    /// Borrowed spec input failed [`ShardSpec`] validation.
    SpecInvalid(ShardSpecInputError),
    /// Handle was stale, foreign, or otherwise not live in this arena.
    InvalidSpecHandle,
    /// Staged entries failed manifest-level checks at build time.
    ManifestInvalid(ManifestValidationError),
}

impl fmt::Display for PreallocShardBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryLimitZero => write!(f, "entry_limit must be > 0"),
            Self::CapMismatch { entry_limit, cap } => {
                write!(f, "entry_limit ({entry_limit}) exceeds builder CAP ({cap})")
            }
            Self::EntryLimitExceedsManifestMax { entry_limit, max } => write!(
                f,
                "entry_limit ({entry_limit}) exceeds MAX_INITIAL_SHARDS ({max})"
            ),
            Self::CapacityExceeded {
                limit,
                current,
                additional,
            } => write!(
                f,
                "entry capacity exceeded: {current} existing + {additional} new > {limit} limit"
            ),
            Self::SlabFull(err) => write!(f, "{err}"),
            Self::RangeInvalid(err) => write!(f, "{err}"),
            Self::PrefixInvalid(err) => write!(f, "{err}"),
            Self::ManifestCtorInvalid(err) => write!(f, "{err}"),
            Self::SpecInvalid(err) => write!(f, "{err}"),
            Self::InvalidSpecHandle => write!(f, "invalid, stale, or foreign shard-spec handle"),
            Self::ManifestInvalid(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PreallocShardBuilderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SlabFull(err) => Some(err),
            Self::RangeInvalid(err) => Some(err),
            Self::PrefixInvalid(err) => Some(err),
            Self::ManifestCtorInvalid(err) => Some(err),
            Self::SpecInvalid(err) => Some(err),
            Self::ManifestInvalid(err) => Some(err),
            Self::EntryLimitZero
            | Self::CapMismatch { .. }
            | Self::EntryLimitExceedsManifestMax { .. }
            | Self::CapacityExceeded { .. }
            | Self::InvalidSpecHandle => None,
        }
    }
}

/// Startup-preallocated shard builder backed by a borrowed arena.
///
/// - Specs are stored in a caller-provided [`ShardArena`] via mutable borrow.
/// - Entries are tracked in fixed-capacity [`InlineVec`].
/// - Public add paths accept borrowed/spec-handle inputs only.
/// - Dropping the builder clears the borrowed arena; use a dedicated arena
///   when specs must outlive builder teardown.
///
/// `CAP` controls the inline entry buffer size. Each entry includes a
/// [`CursorUpdate`] (two optional borrowed slices), so per-entry stack size
/// is target-dependent and larger than a small POD record. A compile-time
/// assertion rejects `CAP > 1024` to keep stack growth bounded.
///
/// The builder does not own cursor key bytes in staged entries:
/// [`CursorUpdate`] payloads are borrowed for lifetime `'a`. This keeps
/// startup registration allocation-light, but callers must ensure borrowed
/// cursor data outlives the [`InitialShardInput`] slice produced by
/// [`Self::build_inputs`].
pub struct PreallocShardBuilder<'a, const CAP: usize> {
    arena: &'a mut ShardArena,
    scratch: ShardSpecScratch,
    entries: InlineVec<BuilderEntry<'a>, CAP>,
    entry_limit: usize,
    next_shard_raw: u64,
}

impl<'a, const CAP: usize> PreallocShardBuilder<'a, CAP> {
    const fn manifest_split_invalid_bounds() -> PreallocShardBuilderError {
        PreallocShardBuilderError::ManifestCtorInvalid(ShardSpecInputError::InvertedRange {
            start_len: ManifestRowKey::ENCODED_LEN,
            end_len: ManifestRowKey::ENCODED_LEN,
        })
    }

    fn manifest_split_count(
        start_row: u64,
        end_row: u64,
        rows_per_shard: u64,
    ) -> Result<usize, PreallocShardBuilderError> {
        if start_row >= end_row || rows_per_shard == 0 {
            return Err(Self::manifest_split_invalid_bounds());
        }
        let span = end_row
            .checked_sub(start_row)
            .ok_or_else(Self::manifest_split_invalid_bounds)?;
        let rounded = span.saturating_add(rows_per_shard - 1);
        let shard_count = rounded / rows_per_shard;
        Ok(usize::try_from(shard_count).unwrap_or(usize::MAX))
    }

    /// Construct a builder borrowing the given arena.
    ///
    /// `entry_limit` caps logical manifest cardinality. Arena slot/byte sizing
    /// is the caller's responsibility — create the [`ShardArena`] with
    /// sufficient capacity before passing it here.
    ///
    /// # Errors
    ///
    /// Returns [`PreallocShardBuilderError`] when `entry_limit` is zero,
    /// exceeds `CAP`, or exceeds [`MAX_INITIAL_SHARDS`].
    pub fn new(
        arena: &'a mut ShardArena,
        entry_limit: usize,
    ) -> Result<Self, PreallocShardBuilderError> {
        const {
            assert!(
                CAP <= 1024,
                "PreallocShardBuilder: CAP > 1024 risks excessive stack usage"
            )
        };

        if entry_limit == 0 {
            return Err(PreallocShardBuilderError::EntryLimitZero);
        }
        if entry_limit > CAP {
            return Err(PreallocShardBuilderError::CapMismatch {
                entry_limit,
                cap: CAP,
            });
        }
        if entry_limit > MAX_INITIAL_SHARDS {
            return Err(PreallocShardBuilderError::EntryLimitExceedsManifestMax {
                entry_limit,
                max: MAX_INITIAL_SHARDS,
            });
        }

        Ok(Self {
            arena,
            scratch: ShardSpecScratch::new(),
            entries: InlineVec::new(),
            entry_limit,
            next_shard_raw: 0,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn entry_limit(&self) -> usize {
        self.entry_limit
    }

    #[must_use]
    pub fn remaining_entries(&self) -> usize {
        self.entry_limit.saturating_sub(self.entries.len())
    }

    /// Reset all builder state for reuse.
    ///
    /// Frees arena-backed specs for all tracked entries, clears the entry
    /// buffer, and restarts shard IDs at 0.
    ///
    /// This invalidates all previously returned [`ShardSpecHandle`] values and
    /// any [`InitialShardInput`] slices built from earlier state.
    pub fn reset(&mut self) {
        let old = std::mem::replace(&mut self.entries, InlineVec::new());
        for entry in old.as_slice() {
            self.arena.free_spec(entry.spec_handle);
        }
        self.scratch = ShardSpecScratch::new();
        self.next_shard_raw = 0;
    }

    fn ensure_entry_capacity(&self, additional: usize) -> Result<(), PreallocShardBuilderError> {
        let current = self.entries.len();
        if current.saturating_add(additional) > self.entry_limit {
            return Err(PreallocShardBuilderError::CapacityExceeded {
                limit: self.entry_limit,
                current,
                additional,
            });
        }
        Ok(())
    }

    fn next_shard_id(&mut self) -> ShardId {
        let shard = ShardId::from_raw(self.next_shard_raw);
        self.next_shard_raw = self
            .next_shard_raw
            .checked_add(1)
            .expect("PreallocShardBuilder: shard-id overflow");
        shard
    }

    fn push_entry(&mut self, spec_handle: ShardSpecHandle, cursor: CursorUpdate<'a>) -> ShardId {
        debug_assert!(
            self.entries.len() < self.entry_limit,
            "push_entry: capacity invariant violated"
        );
        let shard = self.next_shard_id();
        self.entries.push(BuilderEntry {
            shard,
            spec_handle,
            cursor,
        });
        shard
    }

    /// Add a range shard with an initial cursor.
    ///
    /// Equivalent to [`Self::add_range_with_cursor`] with
    /// [`CursorUpdate::initial`].
    pub fn add_range(
        &mut self,
        start: &[u8],
        end: &[u8],
        connector_extra: &[u8],
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.add_range_with_cursor(start, end, connector_extra, CursorUpdate::initial())
    }

    /// Add a range shard with an explicit borrowed cursor update.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::CapacityExceeded`] if `entry_limit`
    ///   would be exceeded.
    /// - [`PreallocShardBuilderError::RangeInvalid`] for invalid bounds or
    ///   metadata sizing.
    /// - [`PreallocShardBuilderError::SlabFull`] if arena storage is exhausted.
    pub fn add_range_with_cursor(
        &mut self,
        start: &[u8],
        end: &[u8],
        connector_extra: &[u8],
        cursor: CursorUpdate<'a>,
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.ensure_entry_capacity(1)?;
        let handle = range_shard_into(self.arena, start, end, connector_extra, &mut self.scratch)
            .map_err(|err| match err {
            ShardIntoError::Build(err) => PreallocShardBuilderError::RangeInvalid(err),
            ShardIntoError::SlabFull(err) => PreallocShardBuilderError::SlabFull(err),
        })?;
        Ok(self.push_entry(handle, cursor))
    }

    /// Add a prefix shard with an initial cursor.
    ///
    /// Equivalent to [`Self::add_prefix_with_cursor`] with
    /// [`CursorUpdate::initial`].
    pub fn add_prefix(
        &mut self,
        prefix: &[u8],
        connector_extra: &[u8],
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.add_prefix_with_cursor(prefix, connector_extra, CursorUpdate::initial())
    }

    /// Add a prefix shard with an explicit borrowed cursor update.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::CapacityExceeded`] if `entry_limit`
    ///   would be exceeded.
    /// - [`PreallocShardBuilderError::PrefixInvalid`] for invalid prefix shape
    ///   (including empty/all-`0xFF` cases) or derived-spec validation failures.
    /// - [`PreallocShardBuilderError::SlabFull`] if arena storage is exhausted.
    pub fn add_prefix_with_cursor(
        &mut self,
        prefix: &[u8],
        connector_extra: &[u8],
        cursor: CursorUpdate<'a>,
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.ensure_entry_capacity(1)?;
        let handle = prefix_shard_into(self.arena, prefix, connector_extra, &mut self.scratch)
            .map_err(|err| match err {
                ShardIntoError::Build(err) => PreallocShardBuilderError::PrefixInvalid(err),
                ShardIntoError::SlabFull(err) => PreallocShardBuilderError::SlabFull(err),
            })?;
        Ok(self.push_entry(handle, cursor))
    }

    /// Add a manifest-row shard with an initial cursor.
    ///
    /// Equivalent to [`Self::add_manifest_with_cursor`] with
    /// [`CursorUpdate::initial`].
    pub fn add_manifest(
        &mut self,
        manifest_id: u64,
        start_row: u64,
        end_row: u64,
        connector_extra: &[u8],
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.add_manifest_with_cursor(
            manifest_id,
            start_row,
            end_row,
            connector_extra,
            CursorUpdate::initial(),
        )
    }

    /// Add a manifest-row shard with an explicit borrowed cursor update.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::CapacityExceeded`] if `entry_limit`
    ///   would be exceeded.
    /// - [`PreallocShardBuilderError::ManifestCtorInvalid`] when manifest row
    ///   bounds or encoded metadata are invalid.
    /// - [`PreallocShardBuilderError::SlabFull`] if arena storage is exhausted.
    pub fn add_manifest_with_cursor(
        &mut self,
        manifest_id: u64,
        start_row: u64,
        end_row: u64,
        connector_extra: &[u8],
        cursor: CursorUpdate<'a>,
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.ensure_entry_capacity(1)?;
        let handle = manifest_shard_into(
            self.arena,
            manifest_id,
            start_row,
            end_row,
            connector_extra,
            &mut self.scratch,
        )
        .map_err(|err| match err {
            ShardIntoError::Build(err) => PreallocShardBuilderError::ManifestCtorInvalid(err),
            ShardIntoError::SlabFull(err) => PreallocShardBuilderError::SlabFull(err),
        })?;
        Ok(self.push_entry(handle, cursor))
    }

    /// Add contiguous range children for a split parent in boundary order.
    ///
    /// `split_points` are interior boundaries between `start` and `end`.
    /// For example, `start=a`, `split_points=[m, t]`, `end=z` yields:
    /// `[a,m)`, `[m,t)`, `[t,z)`.
    ///
    /// Capacity is checked up front for all children to prevent partial writes
    /// on entry-limit exhaustion.
    ///
    /// This method is not transactional for slab exhaustion: if a later child
    /// allocation returns [`PreallocShardBuilderError::SlabFull`], previously
    /// appended children remain staged.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::CapacityExceeded`] if all children would
    ///   not fit in the remaining entry budget.
    /// - [`PreallocShardBuilderError::RangeInvalid`] if any child range is
    ///   invalid.
    /// - [`PreallocShardBuilderError::SlabFull`] if arena storage is exhausted.
    pub fn split_range_by_boundaries(
        &mut self,
        start: &[u8],
        split_points: &[&[u8]],
        end: &[u8],
        connector_extra: &[u8],
    ) -> Result<(), PreallocShardBuilderError> {
        let additional = split_points.len().saturating_add(1);
        self.ensure_entry_capacity(additional)?;

        // Validate all child ranges first so invalid boundaries do not produce
        // partially appended split entries.
        let mut child_start = start;
        for &child_end in split_points {
            range_shard_ref(child_start, child_end, connector_extra, &mut self.scratch)
                .map_err(PreallocShardBuilderError::RangeInvalid)?;
            child_start = child_end;
        }
        range_shard_ref(child_start, end, connector_extra, &mut self.scratch)
            .map_err(PreallocShardBuilderError::RangeInvalid)?;

        let mut child_start = start;
        for &child_end in split_points {
            let handle = range_shard_into(
                self.arena,
                child_start,
                child_end,
                connector_extra,
                &mut self.scratch,
            )
            .map_err(|err| match err {
                ShardIntoError::Build(err) => PreallocShardBuilderError::RangeInvalid(err),
                ShardIntoError::SlabFull(err) => PreallocShardBuilderError::SlabFull(err),
            })?;
            self.push_entry(handle, CursorUpdate::initial());
            child_start = child_end;
        }
        let handle = range_shard_into(
            self.arena,
            child_start,
            end,
            connector_extra,
            &mut self.scratch,
        )
        .map_err(|err| match err {
            ShardIntoError::Build(err) => PreallocShardBuilderError::RangeInvalid(err),
            ShardIntoError::SlabFull(err) => PreallocShardBuilderError::SlabFull(err),
        })?;
        self.push_entry(handle, CursorUpdate::initial());
        Ok(())
    }

    /// Add contiguous manifest-row children by chunking `[start_row, end_row)`.
    ///
    /// Splits the parent interval into fixed-width row chunks of
    /// `rows_per_shard`, with a final short tail chunk when needed.
    /// Capacity is checked up front for all derived children to prevent
    /// partial writes on entry-limit exhaustion.
    ///
    /// This method is not transactional for slab exhaustion: if a later child
    /// allocation returns [`PreallocShardBuilderError::SlabFull`], previously
    /// appended children remain staged.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::CapacityExceeded`] if all chunks would
    ///   not fit in the remaining entry budget.
    /// - [`PreallocShardBuilderError::ManifestCtorInvalid`] for invalid row
    ///   bounds (`start_row >= end_row`), zero `rows_per_shard`, or invalid
    ///   encoded manifest ranges.
    /// - [`PreallocShardBuilderError::SlabFull`] if arena storage is exhausted.
    pub fn split_manifest_by_rows(
        &mut self,
        manifest_id: u64,
        start_row: u64,
        end_row: u64,
        rows_per_shard: u64,
        connector_extra: &[u8],
    ) -> Result<(), PreallocShardBuilderError> {
        let additional = Self::manifest_split_count(start_row, end_row, rows_per_shard)?;
        self.ensure_entry_capacity(additional)?;

        let mut chunk_start = start_row;
        while chunk_start < end_row {
            // Saturating add avoids wrapping on large row IDs, then clamps to
            // the parent end bound to preserve half-open tiling semantics.
            let chunk_end = chunk_start.saturating_add(rows_per_shard).min(end_row);
            debug_assert!(
                chunk_end > chunk_start,
                "split_manifest_by_rows: non-progressing chunk"
            );
            let handle = manifest_shard_into(
                self.arena,
                manifest_id,
                chunk_start,
                chunk_end,
                connector_extra,
                &mut self.scratch,
            )
            .map_err(|err| match err {
                ShardIntoError::Build(err) => PreallocShardBuilderError::ManifestCtorInvalid(err),
                ShardIntoError::SlabFull(err) => PreallocShardBuilderError::SlabFull(err),
            })?;
            self.push_entry(handle, CursorUpdate::initial());
            chunk_start = chunk_end;
        }

        Ok(())
    }

    /// Validate and add a borrowed spec with an initial cursor, copying
    /// bytes into the arena.
    ///
    /// The entry is staged with [`CursorUpdate::initial`]; there is no
    /// `_with_cursor` variant for borrowed-spec inputs.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::CapacityExceeded`] if `entry_limit`
    ///   would be exceeded.
    /// - [`PreallocShardBuilderError::SpecInvalid`] if `spec` fails
    ///   [`ShardSpec::validate_ref`].
    /// - [`PreallocShardBuilderError::SlabFull`] if arena storage is exhausted.
    pub fn add_spec_ref(
        &mut self,
        spec: ShardSpecRef<'a>,
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.ensure_entry_capacity(1)?;
        ShardSpec::validate_ref(spec).map_err(PreallocShardBuilderError::SpecInvalid)?;
        let handle = self
            .arena
            .alloc_spec(spec)
            .map_err(PreallocShardBuilderError::SlabFull)?;
        Ok(self.push_entry(handle, CursorUpdate::initial()))
    }

    /// Add an existing arena-backed spec handle with an initial cursor.
    ///
    /// This is a zero-copy path: no spec bytes are re-allocated. The handle
    /// must reference a live spec in the borrowed arena. Handles from a
    /// different [`ShardArena`] instance or stale generation are rejected by
    /// [`ShardArena::try_view_spec`].
    ///
    /// On success, lifecycle ownership moves to the staged entry: [`Self::reset`]
    /// frees tracked handles and [`Drop`] clears the entire arena.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::CapacityExceeded`] if `entry_limit`
    ///   would be exceeded.
    /// - [`PreallocShardBuilderError::InvalidSpecHandle`] for stale/foreign
    ///   handles, including handles invalidated by [`Self::reset`].
    pub fn add_spec_handle(
        &mut self,
        spec_handle: ShardSpecHandle,
    ) -> Result<ShardId, PreallocShardBuilderError> {
        self.ensure_entry_capacity(1)?;
        if self.arena.try_view_spec(&spec_handle).is_none() {
            return Err(PreallocShardBuilderError::InvalidSpecHandle);
        }
        Ok(self.push_entry(spec_handle, CursorUpdate::initial()))
    }

    /// Materialize borrowed manifest rows for registration.
    ///
    /// Re-validates that every stored handle is still live. Although the builder
    /// exclusively controls its borrowed arena (no external code can free handles
    /// between add and build), this check defends against future refactors that
    /// might introduce non-obvious invalidation paths.
    ///
    /// After handle validation, runs [`validate_manifest`] on the final slice
    /// so callers see registration-time manifest errors before touching
    /// coordinator state.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::InvalidSpecHandle`] when any staged
    ///   handle is stale/foreign.
    /// - [`PreallocShardBuilderError::ManifestInvalid`] when the staged rows
    ///   violate manifest constraints:
    ///   - empty manifest (no entries staged)
    ///   - duplicate shard IDs
    ///   - overlapping key ranges
    ///   - unbounded ranges (empty start or end key)
    ///   - invalid spec (fails [`ShardSpec::validate_ref`])
    ///   - too many shards (exceeds [`MAX_INITIAL_SHARDS`])
    ///   - cursor out of bounds (`last_key` outside spec range)
    ///   - cursor key too large (exceeds `MAX_KEY_SIZE`)
    pub fn build_inputs<'s>(
        &'s self,
    ) -> Result<InlineVec<InitialShardInput<'s>, CAP>, PreallocShardBuilderError>
    where
        'a: 's,
    {
        let mut out = InlineVec::new();
        for entry in self.entries.as_slice() {
            let spec = self
                .arena
                .try_view_spec(&entry.spec_handle)
                .ok_or(PreallocShardBuilderError::InvalidSpecHandle)?;
            out.push(InitialShardInput::new(entry.shard, spec, entry.cursor));
        }
        validate_manifest(out.as_slice()).map_err(PreallocShardBuilderError::ManifestInvalid)?;
        Ok(out)
    }
}

impl<'a, const CAP: usize> Drop for PreallocShardBuilder<'a, CAP> {
    fn drop(&mut self) {
        self.arena.clear();
    }
}

#[cfg(test)]
#[path = "builder_tests.rs"]
mod tests;
