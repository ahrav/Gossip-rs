//! Startup-preallocated shard builder with borrowed-first add paths.
//!
//! The builder stores shard specs in a [`ShardArena`] and tracks entries in a
//! bounded [`InlineVec`], exposing allocation-silent add operations after
//! startup preallocation.
//!
//! Two-phase workflow:
//! - `add_*` methods validate and stage shard specs plus optional borrowed
//!   cursor updates.
//! - [`PreallocShardBuilder::build_inputs`] materializes
//!   [`InitialShardInput`] rows and re-checks manifest-level invariants before
//!   handoff to run registration.
//!
//! Error reporting is intentionally split by phase:
//! - add-time errors isolate constructor/arena capacity failures and reject
//!   invalid external handles passed to [`PreallocShardBuilder::add_spec_handle`].
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
    ShardSpecScratch, manifest_shard_into, prefix_shard_into, range_shard_into,
};
use crate::shard::key_encoding::{PrefixShardError, ShardIntoError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BuilderEntry<'a> {
    shard: ShardId,
    spec_handle: ShardSpecHandle,
    cursor: CursorUpdate<'a>,
}

/// Configuration error for [`PreallocShardBuilder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreallocShardBuilderConfigError {
    /// `entry_limit` was zero.
    EntryLimitZero,
    /// `arena_slots` was zero.
    ArenaSlotsZero,
    /// `arena_bytes` was zero.
    ArenaBytesZero,
    /// `entry_limit` exceeded const generic `CAP`.
    CapMismatch { entry_limit: usize, cap: usize },
    /// `entry_limit` exceeded [`MAX_INITIAL_SHARDS`].
    EntryLimitExceedsManifestMax { entry_limit: usize, max: usize },
}

impl fmt::Display for PreallocShardBuilderConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EntryLimitZero => write!(f, "entry_limit must be > 0"),
            Self::ArenaSlotsZero => write!(f, "arena_slots must be > 0"),
            Self::ArenaBytesZero => write!(f, "arena_bytes must be > 0"),
            Self::CapMismatch { entry_limit, cap } => {
                write!(f, "entry_limit ({entry_limit}) exceeds builder CAP ({cap})")
            }
            Self::EntryLimitExceedsManifestMax { entry_limit, max } => write!(
                f,
                "entry_limit ({entry_limit}) exceeds MAX_INITIAL_SHARDS ({max})"
            ),
        }
    }
}

impl std::error::Error for PreallocShardBuilderConfigError {}

/// Runtime error for [`PreallocShardBuilder`] add/build operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreallocShardBuilderError {
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
            Self::CapacityExceeded { .. } | Self::InvalidSpecHandle => None,
        }
    }
}

/// Startup-preallocated shard builder.
///
/// - Specs are stored in [`ShardArena`] handles.
/// - Entries are tracked in fixed-capacity [`InlineVec`].
/// - Public add paths accept borrowed/spec-handle inputs only.
///
/// The builder does not own cursor key bytes in staged entries:
/// [`CursorUpdate`] payloads are borrowed for lifetime `'a`. This keeps
/// startup registration allocation-light, but callers must ensure borrowed
/// cursor data outlives the [`InitialShardInput`] slice produced by
/// [`Self::build_inputs`].
pub struct PreallocShardBuilder<'a, const CAP: usize> {
    arena: ShardArena,
    scratch: ShardSpecScratch,
    entries: InlineVec<BuilderEntry<'a>, CAP>,
    entry_limit: usize,
    next_shard_raw: u64,
}

impl<'a, const CAP: usize> PreallocShardBuilder<'a, CAP> {
    /// Construct with explicit entry and arena limits.
    ///
    /// `entry_limit` caps logical manifest cardinality; `arena_slots` and
    /// `arena_bytes` cap backing storage. Choosing larger arena budgets than
    /// `entry_limit` is valid when callers expect larger key/metadata payloads
    /// per entry.
    ///
    /// # Errors
    ///
    /// Returns [`PreallocShardBuilderConfigError`] when any limit is zero or
    /// incompatible with `CAP`/[`MAX_INITIAL_SHARDS`].
    pub fn try_with_limits(
        entry_limit: usize,
        arena_slots: usize,
        arena_bytes: usize,
    ) -> Result<Self, PreallocShardBuilderConfigError> {
        if entry_limit == 0 {
            return Err(PreallocShardBuilderConfigError::EntryLimitZero);
        }
        if arena_slots == 0 {
            return Err(PreallocShardBuilderConfigError::ArenaSlotsZero);
        }
        if arena_bytes == 0 {
            return Err(PreallocShardBuilderConfigError::ArenaBytesZero);
        }
        if entry_limit > CAP {
            return Err(PreallocShardBuilderConfigError::CapMismatch {
                entry_limit,
                cap: CAP,
            });
        }
        if entry_limit > MAX_INITIAL_SHARDS {
            return Err(
                PreallocShardBuilderConfigError::EntryLimitExceedsManifestMax {
                    entry_limit,
                    max: MAX_INITIAL_SHARDS,
                },
            );
        }

        Ok(Self {
            arena: ShardArena::with_capacity(arena_slots, arena_bytes),
            scratch: ShardSpecScratch::new(),
            entries: InlineVec::new(),
            entry_limit,
            next_shard_raw: 0,
        })
    }

    /// Convenience constructor where slot capacity matches `entry_limit`.
    ///
    /// Use [`Self::try_with_limits`] when you need extra arena slots for
    /// churn patterns that allocate/free specs before final build.
    pub fn with_capacity(
        entry_limit: usize,
        arena_bytes: usize,
    ) -> Result<Self, PreallocShardBuilderConfigError> {
        Self::try_with_limits(entry_limit, entry_limit, arena_bytes)
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
    /// Frees arena-backed specs, clears entries, and restarts shard IDs at 0.
    ///
    /// This invalidates all previously returned [`ShardSpecHandle`] values and
    /// any [`InitialShardInput`] slices built from earlier state.
    pub fn reset(&mut self) {
        self.arena.clear();
        self.scratch = ShardSpecScratch::new();
        self.entries = InlineVec::new();
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
        let handle = range_shard_into(
            &mut self.arena,
            start,
            end,
            connector_extra,
            &mut self.scratch,
        )
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
        let handle = prefix_shard_into(&mut self.arena, prefix, connector_extra, &mut self.scratch)
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
            &mut self.arena,
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

    /// Validate and add a borrowed spec by copying bytes into the arena.
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
    /// must reference a live spec in this builder's internal arena.
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
    /// Re-validates that every stored handle is still live and then runs
    /// [`validate_manifest`] on the final slice so callers see
    /// registration-time manifest errors before touching coordinator state.
    ///
    /// # Errors
    ///
    /// - [`PreallocShardBuilderError::InvalidSpecHandle`] when any staged
    ///   handle is stale/foreign.
    /// - [`PreallocShardBuilderError::ManifestInvalid`] when the staged rows
    ///   violate manifest constraints (overlap, duplicate IDs, cursor bounds,
    ///   and related checks).
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
        validate_manifest_no_alloc(out.as_slice())
            .map_err(PreallocShardBuilderError::ManifestInvalid)?;
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
