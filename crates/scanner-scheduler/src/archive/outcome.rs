//! Stable, explicit outcome codes for archive scanning.
//!
//! Every archive encounter produces one of three outcomes:
//!
//! 1. **Skipped** — the archive or entry was rejected *before* any payload bytes
//!    were scanned. This covers policy gates (disabled, encrypted, unsupported
//!    format) and pre-scan budget checks (depth, entry count, metadata cap).
//!    Tracked by [`ArchiveSkipReason`] (whole archive) and [`EntrySkipReason`]
//!    (single entry within an archive).
//! 2. **Partial** — scanning *began* and some decompressed bytes were produced
//!    and scanned, but a limit or integrity error stopped further progress.
//!    Already-scanned bytes are **not** discarded — the scan results for those
//!    bytes are retained. Tracked by [`PartialReason`].
//! 3. **Scanned** — the archive (or entry) was fully decompressed and scanned
//!    without hitting any limit.
//!
//! The distinction between Skip and Partial matters because Partial archives
//! still contribute scan results for the bytes they did process, while Skipped
//! archives contribute nothing.
//!
//! [`ArchiveStats`] aggregates per-reason counters and a bounded sample buffer
//! ([`ArchiveSampleRing`]) across all three tiers.  Stats are accumulated
//! per-worker and merged upward via [`ArchiveStats::merge_from`], so all
//! operations are `Copy`-friendly and allocation-free.
//!
//! # Invariants
//!
//! - Enums are `#[repr(u8)]` with explicit discriminants; new variants must be
//!   appended at the end with the next sequential discriminant.
//! - Each enum's `COUNT` constant must equal the last variant's discriminant + 1.
//! - Per-reason counter arrays are indexed by casting the discriminant to `usize`,
//!   so discriminant order and array layout must stay in sync.
//! - The module-level iteration tables (`ARCHIVE_SKIP_REASONS`, etc.) must list
//!   variants in discriminant order; tests assert this alignment.
//! - Samples are bounded and store only a path prefix (never unbounded strings).
//!
//! # Design
//!
//! - Allocation-free on hot paths: all types are `Copy` and fixed-size.
//! - Bounded samples make skip/partial behavior observable in diagnostics
//!   without log spam or unbounded memory growth.
//! - All `record_*` methods compile to no-ops in release builds (gated behind
//!   `cfg!(all(feature = "perf-stats", debug_assertions))`), so the overhead
//!   on production scan throughput is zero.

// -- Reason enums (stable taxonomy) --

/// Why an entire archive container was skipped before any entry payload was scanned.
///
/// Each variant maps to a specific policy gate or pre-scan budget check in
/// [`ArchiveConfig`](super::ArchiveConfig). Discriminants are stable `u8`
/// values used as indices into the per-reason counter array in [`ArchiveStats`].
///
/// The [`BudgetHit::SkipArchive`](super::BudgetHit::SkipArchive) variant wraps
/// this enum when a budget check triggers an archive-level skip.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArchiveSkipReason {
    /// Archive scanning disabled by configuration.
    Disabled = 0,
    /// Format not supported (e.g., 7z) or could not be detected.
    UnsupportedFormat = 1,
    /// Archive indicates encryption in a way that prevents scanning.
    EncryptedArchive = 2,
    /// Nested archive depth exceeded `ArchiveConfig::max_archive_depth`.
    DepthExceeded = 3,
    /// Entry count exceeded `ArchiveConfig::max_entries_per_archive`.
    EntryCountExceeded = 4,
    /// Metadata budget exceeded `ArchiveConfig::max_archive_metadata_bytes`.
    MetadataBudgetExceeded = 5,
    /// Pipeline path budget exceeded while creating virtual entry paths.
    PathBudgetExceeded = 6,
    /// Total decompressed output exceeded `max_total_uncompressed_bytes_per_archive`.
    ArchiveOutputBudgetExceeded = 7,
    /// Root decompressed output exceeded `max_total_uncompressed_bytes_per_root`.
    RootOutputBudgetExceeded = 8,
    /// Archive-level inflation ratio exceeded `max_inflation_ratio`.
    InflationRatioExceeded = 9,
    /// Nested archive requires random access but spill/materialization is not available.
    NeedsRandomAccessNoSpill = 10,
    /// I/O error while reading archive bytes.
    IoError = 11,
    /// Corrupt/malformed archive container.
    Corrupt = 12,
    /// Unsupported container feature (e.g., Zip64 without support).
    UnsupportedFeature = 13,
}

impl ArchiveSkipReason {
    /// Total number of variants. Must equal the last discriminant + 1.
    /// Used to size the per-reason counter array in [`ArchiveStats`].
    pub const COUNT: usize = 14;

    /// Cast to `usize` for use as an array index into per-reason counters.
    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    /// Stable snake_case identifier for telemetry and diagnostic output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::UnsupportedFormat => "unsupported_format",
            Self::EncryptedArchive => "encrypted_archive",
            Self::DepthExceeded => "depth_exceeded",
            Self::EntryCountExceeded => "entry_count_exceeded",
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::PathBudgetExceeded => "path_budget_exceeded",
            Self::ArchiveOutputBudgetExceeded => "archive_output_budget_exceeded",
            Self::RootOutputBudgetExceeded => "root_output_budget_exceeded",
            Self::InflationRatioExceeded => "inflation_ratio_exceeded",
            Self::NeedsRandomAccessNoSpill => "needs_random_access_no_spill",
            Self::IoError => "io_error",
            Self::Corrupt => "corrupt",
            Self::UnsupportedFeature => "unsupported_feature",
        }
    }
}

/// Why a specific entry within an archive was skipped (no payload bytes scanned).
///
/// Entry-level skips do not abort the archive — remaining entries continue to
/// be processed. The [`BudgetHit::SkipEntry`](super::BudgetHit::SkipEntry)
/// variant wraps this enum when a budget or format check triggers an entry skip.
///
/// [`to_partial`](Self::to_partial) provides a lossy mapping into
/// [`PartialReason`] for cases where an entry skip needs to be promoted to
/// an archive-level partial outcome in telemetry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntrySkipReason {
    /// The entry is not a regular file (dir, symlink, device, etc.).
    NonRegular = 0,
    /// Entry path metadata is malformed or exceeds configured component/length caps.
    MalformedPath = 1,
    /// Entry is encrypted.
    EncryptedEntry = 2,
    /// Entry uses an unsupported compression method.
    UnsupportedCompression = 3,
    /// Entry's uncompressed size exceeds `max_uncompressed_bytes_per_entry`.
    EntryOutputBudgetExceeded = 4,
    /// Entry payload is corrupt (e.g., CRC mismatch, invalid stream).
    CorruptPayload = 5,
    /// Entry metadata is corrupt or points outside archive bounds.
    CorruptEntry = 6,
    /// I/O error while reading entry payload bytes.
    IoError = 7,
    /// Unsupported entry feature (e.g., data descriptor without streaming support).
    UnsupportedFeature = 8,
    /// Entry-level inflation ratio exceeded `max_inflation_ratio`.
    EntryInflationRatioExceeded = 9,
}

impl EntrySkipReason {
    /// Total number of variants. Must equal the last discriminant + 1.
    pub const COUNT: usize = 10;

    /// Cast to `usize` for use as an array index into per-reason counters.
    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    /// Stable snake_case identifier for telemetry and diagnostic output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NonRegular => "non_regular",
            Self::MalformedPath => "malformed_path",
            Self::EncryptedEntry => "encrypted_entry",
            Self::UnsupportedCompression => "unsupported_compression",
            Self::EntryOutputBudgetExceeded => "entry_output_budget_exceeded",
            Self::CorruptPayload => "corrupt_payload",
            Self::CorruptEntry => "corrupt_entry",
            Self::IoError => "io_error",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::EntryInflationRatioExceeded => "entry_inflation_ratio_exceeded",
        }
    }

    /// Convert to the corresponding [`PartialReason`] for telemetry recording.
    ///
    /// `EntryInflationRatioExceeded` maps to `PartialReason::InflationRatioExceeded`.
    /// All other variants map to `PartialReason::EntryOutputBudgetExceeded`.
    ///
    /// The match is exhaustive so that adding a new `EntrySkipReason` variant
    /// produces a compile error, forcing an explicit mapping decision.
    pub const fn to_partial(self) -> PartialReason {
        match self {
            Self::EntryOutputBudgetExceeded => PartialReason::EntryOutputBudgetExceeded,
            Self::EntryInflationRatioExceeded => PartialReason::InflationRatioExceeded,
            Self::NonRegular
            | Self::MalformedPath
            | Self::EncryptedEntry
            | Self::UnsupportedCompression
            | Self::CorruptPayload
            | Self::CorruptEntry
            | Self::IoError
            | Self::UnsupportedFeature => PartialReason::EntryOutputBudgetExceeded,
        }
    }
}

/// Why an archive was only partially scanned (some bytes were produced and
/// scanned before a limit or integrity error stopped further progress).
///
/// Unlike skip reasons, a partial outcome means the scanner *did* decompress
/// and scan some entry payloads — those results are retained. The partial
/// reason records *why* scanning stopped early.
///
/// Partial reasons appear in two budget-hit variants:
/// - [`BudgetHit::PartialArchive`](super::BudgetHit::PartialArchive) — the
///   archive itself hit a mid-scan limit.
/// - [`BudgetHit::StopRoot`](super::BudgetHit::StopRoot) — a root-level cap
///   was exhausted, stopping all further archive scanning for this source file.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartialReason {
    /// Metadata parsing hit budget cap.
    MetadataBudgetExceeded = 0,
    /// Path storage hit budget cap.
    PathBudgetExceeded = 1,
    /// Per-entry output budget hit (some bytes in entry may have been scanned).
    EntryOutputBudgetExceeded = 2,
    /// Per-archive output budget hit.
    ArchiveOutputBudgetExceeded = 3,
    /// Per-root output budget hit.
    RootOutputBudgetExceeded = 4,
    /// Scanning stopped due to inflation ratio (archive-level or promoted
    /// entry-level ratio hit).
    InflationRatioExceeded = 5,
    /// Compressed stream corrupted mid-stream (bytes already produced were scanned).
    CompressedStreamCorrupt = 6,
    /// tar container malformed mid-stream.
    MalformedTar = 7,
    /// zip container malformed mid-scan.
    MalformedZip = 8,
    /// Entry count cap hit after scanning began (stop expanding further entries).
    EntryCountExceeded = 9,
    /// Unsupported container feature (e.g., Zip64 sentinel in CDFH).
    UnsupportedFeature = 10,
    /// Wall-clock deadline expired (CPU-exhaustion defense).
    WallClockTimeout = 11,
}

impl PartialReason {
    /// Total number of variants. Must equal the last discriminant + 1.
    pub const COUNT: usize = 12;

    /// Cast to `usize` for use as an array index into per-reason counters.
    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    /// Stable snake_case identifier for telemetry and diagnostic output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::PathBudgetExceeded => "path_budget_exceeded",
            Self::EntryOutputBudgetExceeded => "entry_output_budget_exceeded",
            Self::ArchiveOutputBudgetExceeded => "archive_output_budget_exceeded",
            Self::RootOutputBudgetExceeded => "root_output_budget_exceeded",
            Self::InflationRatioExceeded => "inflation_ratio_exceeded",
            Self::CompressedStreamCorrupt => "compressed_stream_corrupt",
            Self::MalformedTar => "malformed_tar",
            Self::MalformedZip => "malformed_zip",
            Self::EntryCountExceeded => "entry_count_exceeded",
            Self::UnsupportedFeature => "unsupported_feature",
            Self::WallClockTimeout => "wall_clock_timeout",
        }
    }
}

// -- Iteration tables --
//
// Canonical variant lists in discriminant order.  `merge_from` iterates these
// to merge per-reason counter arrays element-by-element, so adding a new
// variant only requires appending here (plus the enum itself and bumping COUNT).
// Tests (`reason_arrays_match_discriminants`) assert that each element's
// discriminant matches its position, catching ordering mistakes at compile-test
// time.
const ARCHIVE_SKIP_REASONS: [ArchiveSkipReason; ArchiveSkipReason::COUNT] = [
    ArchiveSkipReason::Disabled,
    ArchiveSkipReason::UnsupportedFormat,
    ArchiveSkipReason::EncryptedArchive,
    ArchiveSkipReason::DepthExceeded,
    ArchiveSkipReason::EntryCountExceeded,
    ArchiveSkipReason::MetadataBudgetExceeded,
    ArchiveSkipReason::PathBudgetExceeded,
    ArchiveSkipReason::ArchiveOutputBudgetExceeded,
    ArchiveSkipReason::RootOutputBudgetExceeded,
    ArchiveSkipReason::InflationRatioExceeded,
    ArchiveSkipReason::NeedsRandomAccessNoSpill,
    ArchiveSkipReason::IoError,
    ArchiveSkipReason::Corrupt,
    ArchiveSkipReason::UnsupportedFeature,
];

const ENTRY_SKIP_REASONS: [EntrySkipReason; EntrySkipReason::COUNT] = [
    EntrySkipReason::NonRegular,
    EntrySkipReason::MalformedPath,
    EntrySkipReason::EncryptedEntry,
    EntrySkipReason::UnsupportedCompression,
    EntrySkipReason::EntryOutputBudgetExceeded,
    EntrySkipReason::CorruptPayload,
    EntrySkipReason::CorruptEntry,
    EntrySkipReason::IoError,
    EntrySkipReason::UnsupportedFeature,
    EntrySkipReason::EntryInflationRatioExceeded,
];

const PARTIAL_REASONS: [PartialReason; PartialReason::COUNT] = [
    PartialReason::MetadataBudgetExceeded,
    PartialReason::PathBudgetExceeded,
    PartialReason::EntryOutputBudgetExceeded,
    PartialReason::ArchiveOutputBudgetExceeded,
    PartialReason::RootOutputBudgetExceeded,
    PartialReason::InflationRatioExceeded,
    PartialReason::CompressedStreamCorrupt,
    PartialReason::MalformedTar,
    PartialReason::MalformedZip,
    PartialReason::EntryCountExceeded,
    PartialReason::UnsupportedFeature,
    PartialReason::WallClockTimeout,
];

// -- Bounded samples --

/// Classifies a bounded sample along two axes:
///
/// | | Skipped | Partial |
/// |---------|---------|---------|
/// | Archive | `ArchiveSkipped` | `ArchivePartial` |
/// | Entry   | `EntrySkipped`   | `EntryPartial`   |
///
/// The discriminant determines how [`ArchiveSample::reason`] is interpreted:
/// skipped variants use [`ArchiveSkipReason`] / [`EntrySkipReason`] discriminants,
/// while partial variants use [`PartialReason`] discriminants.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleKind {
    ArchiveSkipped = 0,
    ArchivePartial = 1,
    EntrySkipped = 2,
    EntryPartial = 3,
}

/// Maximum samples retained in an [`ArchiveSampleRing`].
pub const ARCHIVE_SAMPLE_MAX: usize = 32;
/// Maximum path prefix bytes stored per sample (truncated beyond this).
pub const ARCHIVE_SAMPLE_PATH_PREFIX_MAX: usize = 192;

/// Bounded sample of a skip/partial outcome, capturing the affected path prefix.
///
/// Fixed-size (`Copy`) so it can live in stack-allocated arrays without heap
/// allocation on the hot path.  Path bytes beyond [`ARCHIVE_SAMPLE_PATH_PREFIX_MAX`]
/// are silently truncated.
///
/// The `reason` field stores a raw `u8` discriminant whose interpretation
/// depends on [`kind`](Self::kind) — see the field-level doc for the mapping.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveSample {
    pub kind: SampleKind,
    /// Raw discriminant of the reason enum that caused this outcome.
    ///
    /// Interpretation depends on [`kind`](Self::kind):
    /// - `ArchiveSkipped` → cast to [`ArchiveSkipReason`]
    /// - `EntrySkipped`   → cast to [`EntrySkipReason`]
    /// - `ArchivePartial` / `EntryPartial` → cast to [`PartialReason`]
    pub reason: u8,
    /// Number of valid bytes in `path_prefix`. Equal to the original path
    /// length or [`ARCHIVE_SAMPLE_PATH_PREFIX_MAX`], whichever is smaller.
    pub path_len: u16,
    pub path_prefix: [u8; ARCHIVE_SAMPLE_PATH_PREFIX_MAX],
}

impl ArchiveSample {
    /// Zero-valued sentinel used to fill empty slots in [`ArchiveSampleRing`].
    pub const EMPTY: Self = Self {
        kind: SampleKind::ArchiveSkipped,
        reason: 0,
        path_len: 0,
        path_prefix: [0u8; ARCHIVE_SAMPLE_PATH_PREFIX_MAX],
    };

    /// Returns the valid (possibly truncated) path bytes for this sample.
    #[inline]
    pub fn path_bytes(&self) -> &[u8] {
        &self.path_prefix[..self.path_len as usize]
    }
}

/// Fixed-capacity sample buffer for skipped/partial outcomes.
///
/// Despite the name, this is a **bounded append buffer**, not a circular ring:
/// once `len` reaches [`ARCHIVE_SAMPLE_MAX`] (32), subsequent pushes increment
/// `dropped` instead of overwriting earlier samples. This preserves the *first*
/// N samples, which are typically the most diagnostic (they show the initial
/// reason scanning stopped, before cascading failures pile up).
///
/// # Guarantees
///
/// - Stores at most [`ARCHIVE_SAMPLE_MAX`] samples; never allocates.
/// - Path bytes per sample are truncated to [`ARCHIVE_SAMPLE_PATH_PREFIX_MAX`].
/// - `dropped` tracks overflow count so callers know whether the buffer
///   captured all events or was saturated.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveSampleRing {
    /// Number of valid samples in `items[..len]`.
    pub len: u8,
    /// Number of samples that could not be stored because the buffer was full.
    /// Incremented via `saturating_add` on push overflow, `wrapping_add` on merge.
    pub dropped: u64,
    pub items: [ArchiveSample; ARCHIVE_SAMPLE_MAX],
}

impl Default for ArchiveSampleRing {
    fn default() -> Self {
        Self {
            len: 0,
            dropped: 0,
            items: [ArchiveSample::EMPTY; ARCHIVE_SAMPLE_MAX],
        }
    }
}

impl ArchiveSampleRing {
    /// Iterate over the valid samples (the first `len` entries).
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, ArchiveSample> {
        self.items[..self.len as usize].iter()
    }

    /// Append a sample if capacity remains; otherwise increment `dropped`.
    ///
    /// `path` is truncated to [`ARCHIVE_SAMPLE_PATH_PREFIX_MAX`] bytes.
    /// The `reason` is the raw `u8` discriminant of the corresponding reason
    /// enum — its interpretation depends on `kind`.
    #[inline]
    pub fn push(&mut self, kind: SampleKind, reason: u8, path: &[u8]) {
        let idx = self.len as usize;
        if idx >= ARCHIVE_SAMPLE_MAX {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }

        let mut s = ArchiveSample::EMPTY;
        s.kind = kind;
        s.reason = reason;

        let n = path.len().min(ARCHIVE_SAMPLE_PATH_PREFIX_MAX);
        s.path_prefix[..n].copy_from_slice(&path[..n]);
        s.path_len = n as u16;

        self.items[idx] = s;
        self.len = self.len.wrapping_add(1);
    }

    /// Merge samples from another buffer into this one.
    ///
    /// Copies as many of `other`'s samples as local capacity allows, then
    /// folds `other.dropped` into `self.dropped` (wrapping).  Any samples
    /// from `other` that do not fit are counted as dropped.
    pub fn merge_from(&mut self, other: &ArchiveSampleRing) {
        for s in other.iter() {
            self.push(s.kind, s.reason, s.path_bytes());
        }
        self.dropped = self.dropped.wrapping_add(other.dropped);
    }
}

// -- Aggregate stats --

/// Per-worker aggregate of archive scanning outcomes.
///
/// Accumulates scalar counters, per-reason breakdowns, and a bounded sample
/// buffer across all archives processed by a single worker thread.  Workers
/// own their `ArchiveStats` without synchronization; after a scan pass the
/// scheduler merges them upward via [`merge_from`](Self::merge_from).
///
/// # Recording gate
///
/// All `record_*` methods are gated behind
/// `cfg!(all(feature = "perf-stats", debug_assertions))`.  In release builds
/// the gate is a compile-time `false` and the compiler eliminates every
/// method body entirely (verified via `cargo asm`).  This means production
/// builds pay zero runtime cost for carrying these stats, while debug/test
/// builds get full observability.
///
/// # Arithmetic
///
/// All counters use wrapping arithmetic.  Overflow is benign because these
/// counters are diagnostic only — they are never used for correctness
/// decisions.  Wrapping avoids panics without needing checked arithmetic on
/// every hot-path increment.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveStats {
    // -- Top-level archive counters --
    pub archives_seen: u64,
    pub archives_scanned: u64,
    pub archives_skipped: u64,
    pub archives_partial: u64,

    // -- Entry counters --
    pub entries_scanned: u64,
    pub entries_skipped: u64,

    // -- Path anomaly counters --
    pub paths_truncated: u64,
    pub paths_had_traversal: u64,
    pub paths_component_cap_exceeded: u64,

    // -- Per-reason breakdowns (indexed by discriminant via `as_usize()`) --
    pub archive_skip_reasons: [u64; ArchiveSkipReason::COUNT],
    pub entry_skip_reasons: [u64; EntrySkipReason::COUNT],
    /// Shared across archive-partial and entry-partial recordings.
    /// A single partial_reasons counter is bumped regardless of whether the
    /// partial event originated at the archive or entry level.
    pub partial_reasons: [u64; PartialReason::COUNT],

    pub samples: ArchiveSampleRing,
}

impl Default for ArchiveStats {
    fn default() -> Self {
        Self {
            archives_seen: 0,
            archives_scanned: 0,
            archives_skipped: 0,
            archives_partial: 0,
            entries_scanned: 0,
            entries_skipped: 0,
            paths_truncated: 0,
            paths_had_traversal: 0,
            paths_component_cap_exceeded: 0,
            archive_skip_reasons: [0; ArchiveSkipReason::COUNT],
            entry_skip_reasons: [0; EntrySkipReason::COUNT],
            partial_reasons: [0; PartialReason::COUNT],
            samples: ArchiveSampleRing::default(),
        }
    }
}

impl ArchiveStats {
    /// Returns `true` only when both `perf-stats` and `debug_assertions` are active.
    ///
    /// In release builds this is a compile-time `false`, so the compiler
    /// eliminates every `record_*` method body entirely — verified via
    /// `cargo asm`: `record_archive_seen` (and siblings) are absent from
    /// the release binary.
    #[inline(always)]
    fn recording_enabled() -> bool {
        cfg!(all(feature = "perf-stats", debug_assertions))
    }

    /// Returns `true` if any archive or entry was seen, scanned, skipped,
    /// or had path anomalies.  Used to gate summary output — callers skip
    /// formatting when no archive work occurred at all.
    #[inline]
    pub fn has_activity(&self) -> bool {
        self.archives_seen != 0
            || self.archives_scanned != 0
            || self.archives_skipped != 0
            || self.archives_partial != 0
            || self.entries_scanned != 0
            || self.entries_skipped != 0
            || self.paths_truncated != 0
            || self.paths_had_traversal != 0
            || self.paths_component_cap_exceeded != 0
    }

    #[inline]
    pub fn record_archive_seen(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.archives_seen = self.archives_seen.wrapping_add(1);
    }

    #[inline]
    pub fn record_archive_scanned(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.archives_scanned = self.archives_scanned.wrapping_add(1);
    }

    /// Record an archive-level skip.  When `sample` is true and the ring has
    /// capacity, a bounded path sample is captured for later diagnostics.
    ///
    /// (The `let _ = ...` in the disabled path suppresses unused-parameter
    /// warnings; the same pattern appears in all `record_*` siblings.)
    #[inline]
    pub fn record_archive_skipped(
        &mut self,
        reason: ArchiveSkipReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        self.archives_skipped = self.archives_skipped.wrapping_add(1);
        let idx = reason.as_usize();
        self.archive_skip_reasons[idx] = self.archive_skip_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::ArchiveSkipped, reason as u8, display_path);
        }
    }

    /// Record an archive-level partial outcome (scanning began but stopped early).
    ///
    /// Increments `archives_partial` and the per-reason `partial_reasons` counter.
    #[inline]
    pub fn record_archive_partial(
        &mut self,
        reason: PartialReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        self.archives_partial = self.archives_partial.wrapping_add(1);
        let idx = reason.as_usize();
        self.partial_reasons[idx] = self.partial_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::ArchivePartial, reason as u8, display_path);
        }
    }

    #[inline]
    pub fn record_entry_scanned(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.entries_scanned = self.entries_scanned.wrapping_add(1);
    }

    /// Record an entry-level skip (entry rejected before any payload bytes were scanned).
    ///
    /// Increments `entries_skipped` and the per-reason `entry_skip_reasons` counter.
    #[inline]
    pub fn record_entry_skipped(
        &mut self,
        reason: EntrySkipReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        self.entries_skipped = self.entries_skipped.wrapping_add(1);
        let idx = reason.as_usize();
        self.entry_skip_reasons[idx] = self.entry_skip_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::EntrySkipped, reason as u8, display_path);
        }
    }

    /// Record an entry-level partial outcome (entry scanning began but stopped early).
    ///
    /// Bumps the per-reason `partial_reasons` counter and optionally captures
    /// a sample, but does **not** increment `entries_skipped` or any
    /// archive-level counter.  The entry was not "skipped" — it was partially
    /// scanned, so the top-level skip counter is not touched.
    #[inline]
    pub fn record_entry_partial(
        &mut self,
        reason: PartialReason,
        display_path: &[u8],
        sample: bool,
    ) {
        if !Self::recording_enabled() {
            let _ = (reason, display_path, sample);
            return;
        }
        let idx = reason.as_usize();
        self.partial_reasons[idx] = self.partial_reasons[idx].wrapping_add(1);

        if sample {
            self.samples
                .push(SampleKind::EntryPartial, reason as u8, display_path);
        }
    }

    #[inline]
    pub fn record_path_truncated(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.paths_truncated = self.paths_truncated.wrapping_add(1);
    }

    #[inline]
    pub fn record_path_had_traversal(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.paths_had_traversal = self.paths_had_traversal.wrapping_add(1);
    }

    #[inline]
    pub fn record_component_cap_exceeded(&mut self) {
        if !Self::recording_enabled() {
            return;
        }
        self.paths_component_cap_exceeded = self.paths_component_cap_exceeded.wrapping_add(1);
    }

    /// Merge counters and bounded samples from another stats instance.
    ///
    /// All counters are merged via wrapping addition; samples respect the
    /// local `ARCHIVE_SAMPLE_MAX` capacity.
    pub fn merge_from(&mut self, other: &ArchiveStats) {
        if !Self::recording_enabled() {
            let _ = other;
            return;
        }
        self.archives_seen = self.archives_seen.wrapping_add(other.archives_seen);
        self.archives_scanned = self.archives_scanned.wrapping_add(other.archives_scanned);
        self.archives_skipped = self.archives_skipped.wrapping_add(other.archives_skipped);
        self.archives_partial = self.archives_partial.wrapping_add(other.archives_partial);
        self.entries_scanned = self.entries_scanned.wrapping_add(other.entries_scanned);
        self.entries_skipped = self.entries_skipped.wrapping_add(other.entries_skipped);
        self.paths_truncated = self.paths_truncated.wrapping_add(other.paths_truncated);
        self.paths_had_traversal = self
            .paths_had_traversal
            .wrapping_add(other.paths_had_traversal);
        self.paths_component_cap_exceeded = self
            .paths_component_cap_exceeded
            .wrapping_add(other.paths_component_cap_exceeded);

        for r in ARCHIVE_SKIP_REASONS.iter() {
            let idx = r.as_usize();
            self.archive_skip_reasons[idx] =
                self.archive_skip_reasons[idx].wrapping_add(other.archive_skip_reasons[idx]);
        }
        for r in ENTRY_SKIP_REASONS.iter() {
            let idx = r.as_usize();
            self.entry_skip_reasons[idx] =
                self.entry_skip_reasons[idx].wrapping_add(other.entry_skip_reasons[idx]);
        }
        for r in PARTIAL_REASONS.iter() {
            let idx = r.as_usize();
            self.partial_reasons[idx] =
                self.partial_reasons[idx].wrapping_add(other.partial_reasons[idx]);
        }

        self.samples.merge_from(&other.samples);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_match_variant_space() {
        assert_eq!(
            ArchiveSkipReason::COUNT,
            ArchiveSkipReason::UnsupportedFeature as usize + 1
        );
        assert_eq!(
            EntrySkipReason::COUNT,
            EntrySkipReason::EntryInflationRatioExceeded as usize + 1
        );
        assert_eq!(
            PartialReason::COUNT,
            PartialReason::WallClockTimeout as usize + 1
        );
    }

    #[test]
    fn reason_arrays_match_discriminants() {
        for r in ARCHIVE_SKIP_REASONS.iter() {
            assert_eq!(ARCHIVE_SKIP_REASONS[r.as_usize()], *r);
        }
        for r in ENTRY_SKIP_REASONS.iter() {
            assert_eq!(ENTRY_SKIP_REASONS[r.as_usize()], *r);
        }
        for r in PARTIAL_REASONS.iter() {
            assert_eq!(PARTIAL_REASONS[r.as_usize()], *r);
        }
    }
}
