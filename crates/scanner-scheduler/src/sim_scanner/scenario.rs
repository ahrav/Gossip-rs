//! Scenario schema for scanner simulation runs.
//!
//! The schema is designed to be serialized as part of repro artifacts. It keeps
//! filesystem contents, synthetic rules, and expected secrets explicit and
//! deterministic.

use serde::{Deserialize, Serialize};

use crate::archive::ArchiveConfig;
use crate::sim::fs::{SimFsSpec, SimPath};

/// Configuration for a single simulation run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunConfig {
    /// Number of simulated workers.
    pub workers: u32,
    /// Chunk size used for scanning.
    pub chunk_size: u32,
    /// Overlap bytes between chunks.
    pub overlap: u32,
    /// Maximum number of in-flight filesystem objects.
    pub max_in_flight_objects: u32,
    /// Maximum number of buffers in the simulated pool.
    pub buffer_pool_cap: u32,

    /// Maximum file size in bytes to scan.
    ///
    /// Files larger than this are skipped at open time. Discovery may also
    /// pre-filter using size hints.
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Maximum number of simulation steps before declaring a hang.
    pub max_steps: u64,

    /// Maximum depth for transform decoding.
    pub max_transform_depth: u32,
    /// Whether to scan UTF-16 variants.
    pub scan_utf16_variants: bool,

    /// Archive scanning configuration for simulation runs.
    ///
    /// Used both for scan behavior and for deterministic virtual-path mapping.
    #[serde(default)]
    pub archive: ArchiveConfig,

    /// Number of stability runs per scenario (different schedules).
    pub stability_runs: u32,

    /// Test-only countdown for deterministic wall-clock timeout testing.
    ///
    /// When set, `is_deadline_expired()` fires after exactly this many calls
    /// instead of consulting the real clock. See
    /// [`crate::archive::ArchiveBudgets::set_deadline_check_countdown`] for semantics.
    #[cfg(any(test, feature = "sim-harness"))]
    #[serde(skip)]
    pub archive_deadline_countdown: Option<u32>,
}

impl RunConfig {
    /// Clamp `overlap` and `chunk_size` so they satisfy the engine's minimum
    /// overlap requirement.
    ///
    /// After calling this, `self.overlap >= required_overlap` and
    /// `self.chunk_size >= self.overlap`. This is the single source of truth
    /// for the two-pass adjustment pattern used by mutation test harnesses,
    /// so scenario producers and replay code do not drift on boundary semantics.
    pub fn adjust_for_overlap(&mut self, required_overlap: u32) {
        if self.overlap < required_overlap {
            self.overlap = required_overlap;
        }
        if self.chunk_size < self.overlap {
            self.chunk_size = self.overlap;
        }
    }
}

fn default_max_file_size() -> u64 {
    u64::MAX
}

/// Top-level scenario schema for scanner simulations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scenario {
    /// Schema version for forward-compatible evolution.
    pub schema_version: u32,
    /// Filesystem layout and file contents.
    pub fs: SimFsSpec,
    /// Synthetic rules used to generate expected findings.
    pub rule_suite: RuleSuiteSpec,
    /// Expected secrets for ground-truth validation.
    pub expected: Vec<ExpectedSecret>,
    /// Archive specs for deterministic generation and minimization.
    #[serde(default)]
    pub archives: Vec<ArchiveFileSpec>,
}

/// Disposition for expected secrets in archive scenarios.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum ExpectedDisposition {
    /// Secret must be found if the object was fully observed.
    #[default]
    MustFind,
    /// Secret may be missed for documented reasons (corruption, budgets, etc).
    /// Oracles treat this as non-fatal when reporting coverage gaps.
    MayMiss { reason: String },
}

/// Expected secret inserted by the scenario generator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpectedSecret {
    pub path: SimPath,
    pub rule_id: u32,
    /// Span in the root/original buffer (encoded bytes, not decoded).
    pub root_span: SpanU32,
    /// Representation used to derive the secret bytes.
    pub repr: SecretRepr,
    /// Whether the secret must be found or may be missed.
    #[serde(default)]
    pub disposition: ExpectedDisposition,
}

pub use crate::sim::mutation::SecretRepr;

/// Byte span with half-open semantics `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpanU32 {
    pub start: u32,
    pub end: u32,
}

impl SpanU32 {
    #[inline(always)]
    pub fn new(start: u32, end: u32) -> Self {
        debug_assert!(start <= end);
        Self { start, end }
    }
}

/// Synthetic rule suite specification for scenario generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSuiteSpec {
    pub schema_version: u32,
    pub rules: Vec<SyntheticRuleSpec>,
}

/// Minimal synthetic rule description used by the sim harness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyntheticRuleSpec {
    pub rule_id: u32,
    pub name: String,
    /// Anchor bytes inserted alongside the secret to force candidate windows.
    pub anchors: Vec<Vec<u8>>,
    /// Validation radius in bytes around an anchor hit.
    #[serde(default = "default_rule_radius")]
    pub radius: u32,
    /// Regex pattern used by the engine during validation.
    pub regex: String,
}

fn default_rule_radius() -> u32 {
    64
}

/// Archive kind used by the simulation schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArchiveKindSpec {
    Gzip,
    Bzip2,
    Tar,
    TarGz,
    TarBz2,
    Zip,
}

/// Archive specification for deterministic materialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveFileSpec {
    /// Filesystem path for the archive file itself.
    pub root_path: SimPath,
    /// Archive container kind to materialize.
    pub kind: ArchiveKindSpec,
    /// Entry list in deterministic order.
    pub entries: Vec<ArchiveEntrySpec>,
    /// Optional corruption applied after materialization.
    #[serde(default)]
    pub corruption: Option<ArchiveCorruptionSpec>,
}

/// Entry specification for archive materialization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveEntrySpec {
    /// Raw entry name bytes (not canonicalized).
    pub name_bytes: Vec<u8>,
    /// Uncompressed payload bytes for the entry.
    pub payload: Vec<u8>,
    /// Compression mode (used by ZIP materialization).
    pub compression: EntryCompressionSpec,
    /// Whether the entry is marked as encrypted (ZIP flag only).
    #[serde(default)]
    pub encrypted: bool,
    /// Entry kind used to set the archive header type.
    pub kind: EntryKindSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryCompressionSpec {
    /// Store payload without compression.
    Store,
    /// Deflate-compress payload (ZIP only).
    Deflate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKindSpec {
    /// Regular file entry with payload bytes.
    RegularFile,
    /// Directory entry (payload is ignored).
    Directory,
    /// Symlink entry (payload is ignored).
    Symlink,
    /// Other/non-regular entry (payload is ignored).
    Other,
}

/// Archive-level corruption used for malformed variants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ArchiveCorruptionSpec {
    /// Truncate the final archive bytes to a fixed length.
    TruncateTo { len: u64 },
}
