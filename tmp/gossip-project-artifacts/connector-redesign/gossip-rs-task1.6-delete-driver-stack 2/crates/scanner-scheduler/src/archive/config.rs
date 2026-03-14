//! Archive scanning policy and hard limits.
//!
//! [`ArchiveConfig`] is the single source of truth for every resource cap
//! applied during archive expansion. [`ArchiveBudgets`](super::ArchiveBudgets)
//! copies these caps at construction time, [`ArchiveScratch`](super::ArchiveScratch)
//! uses them to preallocate buffers, and path canonicalization reads the path
//! length/budget fields.
//!
//! # Limit Hierarchy
//!
//! Limits are nested: an entry cap must fit within its archive cap, which must
//! fit within the root cap. [`ArchiveConfig::validate`] enforces this ordering
//! so that downstream code can rely on `entry <= archive <= root` without
//! rechecking.
//!
//! ```text
//! Root  (max_total_uncompressed_bytes_per_root)
//!  └─ Archive  (max_total_uncompressed_bytes_per_archive)
//!      └─ Entry  (max_uncompressed_bytes_per_entry)
//! ```
//!
//! # Invariants
//!
//! - All limits are hard bounds and must be internally consistent.
//! - Archives are treated as hostile input: sizes, counts, and paths are
//!   untrusted. Every field here exists to bound a specific attack vector
//!   (zip bombs, path bombs, metadata floods, CPU exhaustion).
//! - [`validate`](ArchiveConfig::validate) must pass before the config is
//!   used. It checks both non-zero requirements and cross-field ordering.
//!
//! # Design Notes
//!
//! - Defaults are safety-first: archive scanning is enabled by default with
//!   conservative caps that prevent unbounded resource consumption.
//! - Limits are shared across execution modes (pipeline and scheduler) to
//!   keep behavior consistent regardless of the calling context.
//! - Policy enums ([`EncryptedPolicy`], [`UnsupportedPolicy`]) use an
//!   escalation ladder (skip -> fail archive -> fail run) so operators can
//!   tune severity without code changes.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Default wall-clock deadline (seconds) per root-level archive scan.
///
/// Production scanners should opt in to a wall-clock deadline for CPU-exhaustion
/// defense. This value bounds the worst-case scan time for a single root file
/// while being generous enough for large legitimate archives.
pub const DEFAULT_WALL_CLOCK_SECS_PER_ROOT: u64 = 30;

/// Maximum allowed value for `max_wall_clock_secs_per_root` (24 hours).
///
/// Values beyond this are almost certainly configuration errors. More
/// importantly, very large values can cause `Instant::now().checked_add()`
/// to return `None`, silently disabling the deadline. This cap ensures
/// the deadline always arms successfully.
pub const MAX_WALL_CLOCK_SECS_PER_ROOT: u64 = 86_400;

/// Policy for how to treat encrypted archives or encrypted entries.
///
/// Variants form an escalation ladder from least to most disruptive. The
/// default (`SkipWithTelemetry`) silently skips encrypted content, which is
/// the safest choice when the scanner cannot decrypt. Operators who require
/// full coverage can escalate to `FailArchive` or `FailRun` to surface
/// encryption as an error rather than a gap.
///
/// Enforced in the archive scan functions and the pipeline/scheduler paths.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum EncryptedPolicy {
    /// Skip encrypted content and increment telemetry counters.
    #[default]
    SkipWithTelemetry = 0,
    /// Treat the current archive as failed and continue scanning other roots.
    FailArchive = 1,
    /// Abort the entire scan.
    FailRun = 2,
}

/// Policy for how to treat unsupported archive formats or unsupported features.
///
/// Same escalation ladder as [`EncryptedPolicy`]. The default skips
/// unsupported content (e.g. 7z, RAR, or Zip64 features the scanner does
/// not handle) and records telemetry so coverage gaps are observable.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum UnsupportedPolicy {
    /// Skip unsupported content and increment telemetry counters.
    #[default]
    SkipWithTelemetry = 0,
    /// Treat the current archive as failed and continue scanning other roots.
    FailArchive = 1,
    /// Abort the entire scan.
    FailRun = 2,
}

/// Shared archive scanning configuration (pipeline + scheduler).
///
/// All limits are hard bounds. Archive code must treat archive metadata and
/// payload as hostile: sizes, counts, paths, and offsets are untrusted.
///
/// Construct with [`Default::default`] for safe defaults, then override
/// fields as needed. Always call [`validate`](Self::validate) before use to
/// catch ordering violations (`entry <= archive <= root`) and zero-value
/// fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Master enable switch.
    ///
    /// When `false`, archive scanning is entirely bypassed: the scanner
    /// treats archive files as opaque blobs, producing no nested entries.
    /// All other fields are still validated (even when disabled) so configs
    /// can be checked in tests without toggling this flag.
    pub enabled: bool,

    /// Maximum nested archive depth (e.g. zip-inside-tar-inside-gz).
    ///
    /// Controls the preallocated frame stack size in
    /// [`ArchiveBudgets`](super::ArchiveBudgets). A depth of 3 handles
    /// the vast majority of real-world nesting; deeper nesting is almost
    /// always adversarial.
    pub max_archive_depth: u8,

    /// Maximum number of entries processed per archive container.
    ///
    /// Bounds the entry-counting loop in scan functions. Exceeding this
    /// cap triggers an `EntryCountExceeded` skip/partial outcome.
    pub max_entries_per_archive: u32,

    /// Maximum decompressed bytes scanned for a single entry.
    ///
    /// [`ArchiveBudgets`](super::ArchiveBudgets) clamps this value to
    /// `ENTRY_NOT_OPEN - 1` (`u64::MAX - 1`) at construction to prevent
    /// a sentinel collision in the budget tracker's entry-open state.
    /// In practice, values beyond a few hundred MiB are unlikely to be
    /// useful; the default is 64 MiB.
    pub max_uncompressed_bytes_per_entry: u64,

    /// Maximum total decompressed bytes scanned across all entries in a
    /// single archive container. Must be >= `max_uncompressed_bytes_per_entry`.
    pub max_total_uncompressed_bytes_per_archive: u64,

    /// Maximum total decompressed bytes scanned across all archives rooted
    /// at one source file. Must be >= `max_total_uncompressed_bytes_per_archive`.
    pub max_total_uncompressed_bytes_per_root: u64,

    /// Maximum bytes of archive metadata (central directory, headers, etc.)
    /// parsed per archive container.
    ///
    /// Bounds parsing of zip central directories, tar headers, and similar
    /// structural overhead that precedes payload data. Prevents
    /// metadata-flood attacks where a crafted archive has an enormous
    /// header section but trivial payload.
    pub max_archive_metadata_bytes: u64,

    /// Maximum tolerated inflation ratio (`decompressed / compressed`).
    ///
    /// Enforced at both archive and entry scopes. Ratio tracking is
    /// best-effort because compressed-input accounting depends on the
    /// decompressor reporting bytes consumed, which not all formats
    /// expose precisely (e.g. gzip streams do not report per-entry
    /// compressed sizes). When compressed input is zero (unknown), the
    /// ratio check is skipped to avoid false positives.
    pub max_inflation_ratio: u32,

    /// Maximum display-path length (bytes) for a single canonicalized
    /// archive entry.
    ///
    /// Used by [`EntryPathCanonicalizer`](super::EntryPathCanonicalizer)
    /// to bound output. Paths exceeding this are truncated with a
    /// deterministic hash suffix.
    pub max_virtual_path_len_per_entry: usize,

    /// Maximum total virtual path bytes stored across all entries in one
    /// archive container.
    ///
    /// Protects the pipeline's path arena from unbounded growth when an
    /// archive contains many entries with long paths. Must be >=
    /// `max_virtual_path_len_per_entry`.
    pub max_virtual_path_bytes_per_archive: usize,

    /// Optional wall-clock deadline (seconds) per root-level archive scan.
    ///
    /// When set, each `reset()` call arms an `Instant`-based deadline in
    /// [`ArchiveBudgets`](super::ArchiveBudgets). Nested archives share the
    /// root's deadline (they call `enter_archive()` without `reset()`).
    ///
    /// `None` disables the deadline entirely -- no `Instant` is created and
    /// budget tracking remains fully deterministic. Production scanners
    /// should opt in explicitly (e.g., `Some(30)`).
    #[serde(default)]
    pub max_wall_clock_secs_per_root: Option<u64>,

    /// Policy for encrypted content.
    pub encrypted_policy: EncryptedPolicy,
    /// Policy for unsupported content.
    pub unsupported_policy: UnsupportedPolicy,
}

/// Validation error returned by [`ArchiveConfig::validate`].
///
/// Each variant corresponds to a violated invariant or ordering constraint.
/// Callers should treat this as a configuration bug (not hostile input).
///
/// The `*Zero` variants catch obviously invalid caps (you cannot scan zero
/// bytes or zero entries). The compound variants (`*TooSmall`) enforce the
/// nesting order: inner caps must not exceed their enclosing scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArchiveConfigError {
    MaxArchiveDepthZero,
    MaxEntriesPerArchiveZero,
    MaxUncompressedBytesPerEntryZero,
    MaxTotalUncompressedBytesPerArchiveZero,
    MaxTotalUncompressedBytesPerRootZero,
    /// Per-archive byte cap is smaller than the per-entry cap, which would
    /// make it impossible for any single entry to use its full allowance.
    ArchiveBytesCapTooSmall {
        per_entry: u64,
        per_archive: u64,
    },
    /// Per-root byte cap is smaller than the per-archive cap, violating the
    /// `entry <= archive <= root` nesting invariant.
    RootBytesCapTooSmall {
        per_archive: u64,
        per_root: u64,
    },
    MaxArchiveMetadataBytesZero,
    MaxInflationRatioZero,
    MaxVirtualPathLenPerEntryZero,
    MaxVirtualPathBytesPerArchiveZero,
    /// Per-archive path budget is smaller than the max path length for a
    /// single entry, meaning even one entry could never store its full path.
    PathBudgetTooSmall {
        per_entry: usize,
        per_archive: usize,
    },
    MaxWallClockSecsPerRootZero,
    /// Wall-clock deadline is so large that `Instant::now().checked_add()`
    /// could return `None`, silently disabling the deadline.
    MaxWallClockSecsPerRootTooLarge {
        value: u64,
        max: u64,
    },
}

impl fmt::Display for ArchiveConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveConfigError::MaxArchiveDepthZero => {
                write!(f, "max_archive_depth must be > 0")
            }
            ArchiveConfigError::MaxEntriesPerArchiveZero => {
                write!(f, "max_entries_per_archive must be > 0")
            }
            ArchiveConfigError::MaxUncompressedBytesPerEntryZero => {
                write!(f, "max_uncompressed_bytes_per_entry must be > 0")
            }
            ArchiveConfigError::MaxTotalUncompressedBytesPerArchiveZero => {
                write!(f, "max_total_uncompressed_bytes_per_archive must be > 0")
            }
            ArchiveConfigError::MaxTotalUncompressedBytesPerRootZero => {
                write!(f, "max_total_uncompressed_bytes_per_root must be > 0")
            }
            ArchiveConfigError::ArchiveBytesCapTooSmall {
                per_entry,
                per_archive,
            } => write!(
                f,
                "per-archive byte cap must be >= per-entry byte cap (entry={per_entry}, archive={per_archive})"
            ),
            ArchiveConfigError::RootBytesCapTooSmall {
                per_archive,
                per_root,
            } => write!(
                f,
                "per-root byte cap must be >= per-archive byte cap (archive={per_archive}, root={per_root})"
            ),
            ArchiveConfigError::MaxArchiveMetadataBytesZero => {
                write!(f, "max_archive_metadata_bytes must be > 0")
            }
            ArchiveConfigError::MaxInflationRatioZero => {
                write!(f, "max_inflation_ratio must be > 0")
            }
            ArchiveConfigError::MaxVirtualPathLenPerEntryZero => {
                write!(f, "max_virtual_path_len_per_entry must be > 0")
            }
            ArchiveConfigError::MaxVirtualPathBytesPerArchiveZero => {
                write!(f, "max_virtual_path_bytes_per_archive must be > 0")
            }
            ArchiveConfigError::PathBudgetTooSmall {
                per_entry,
                per_archive,
            } => write!(
                f,
                "per-archive path budget must be >= per-entry max length (entry={per_entry}, archive={per_archive})"
            ),
            ArchiveConfigError::MaxWallClockSecsPerRootZero => {
                write!(f, "max_wall_clock_secs_per_root must be > 0 when set")
            }
            ArchiveConfigError::MaxWallClockSecsPerRootTooLarge { value, max } => write!(
                f,
                "max_wall_clock_secs_per_root ({value}) exceeds maximum ({max})"
            ),
        }
    }
}

/// Defaults are conservative and optimized for safety over throughput.
///
/// Rationale for key values:
/// - **depth 3**: covers common nesting (e.g. `.tar.gz` containing a `.zip`);
///   deeper nesting is almost always adversarial.
/// - **4096 entries**: generous for legitimate archives, tight enough to bound
///   CPU in entry-counting loops.
/// - **64 MiB per entry, 256 MiB per archive, 512 MiB per root**: chosen so
///   the hierarchy satisfies `entry <= archive <= root` and limits peak memory
///   to well under 1 GiB even with concurrent workers.
/// - **128x inflation ratio**: accommodates high-compression formats (e.g.
///   highly repetitive data in deflate) while still catching classic zip bombs.
/// - **No wall-clock deadline**: keeps defaults fully deterministic; production
///   deployments should opt in to a deadline (e.g. 30s) for CPU-exhaustion
///   defense.
impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: true,

            max_archive_depth: 3,
            max_entries_per_archive: 4096,
            max_uncompressed_bytes_per_entry: 64 * 1024 * 1024, // 64 MiB
            max_total_uncompressed_bytes_per_archive: 256 * 1024 * 1024, // 256 MiB
            max_total_uncompressed_bytes_per_root: 512 * 1024 * 1024, // 512 MiB

            max_archive_metadata_bytes: 16 * 1024 * 1024, // 16 MiB
            max_inflation_ratio: 128,

            max_virtual_path_len_per_entry: 1024,
            max_virtual_path_bytes_per_archive: 1024 * 1024, // 1 MiB

            max_wall_clock_secs_per_root: None,

            encrypted_policy: EncryptedPolicy::SkipWithTelemetry,
            unsupported_policy: UnsupportedPolicy::SkipWithTelemetry,
        }
    }
}

impl ArchiveConfig {
    /// Validate cross-field invariants.
    ///
    /// Checks two classes of constraints:
    ///
    /// 1. **Non-zero**: every cap must be positive (a zero cap would make the
    ///    corresponding feature unusable).
    /// 2. **Nesting order**: `entry <= archive <= root` for byte budgets, and
    ///    `per_entry_path_len <= per_archive_path_budget` for path budgets.
    ///
    /// Validation runs even when `enabled == false` so that configs can be
    /// checked in tests without toggling the feature flag.
    ///
    /// This is cheap (no allocation, no I/O) and should be called once at
    /// startup. Returns the first violated constraint; fix and re-validate.
    pub fn validate(&self) -> Result<(), ArchiveConfigError> {
        // Always validate even when disabled, so configs can be checked in
        // tests without enabling the feature.
        if self.max_archive_depth == 0 {
            return Err(ArchiveConfigError::MaxArchiveDepthZero);
        }
        if self.max_entries_per_archive == 0 {
            return Err(ArchiveConfigError::MaxEntriesPerArchiveZero);
        }
        if self.max_uncompressed_bytes_per_entry == 0 {
            return Err(ArchiveConfigError::MaxUncompressedBytesPerEntryZero);
        }
        if self.max_total_uncompressed_bytes_per_archive == 0 {
            return Err(ArchiveConfigError::MaxTotalUncompressedBytesPerArchiveZero);
        }
        if self.max_total_uncompressed_bytes_per_root == 0 {
            return Err(ArchiveConfigError::MaxTotalUncompressedBytesPerRootZero);
        }
        if self.max_total_uncompressed_bytes_per_archive < self.max_uncompressed_bytes_per_entry {
            return Err(ArchiveConfigError::ArchiveBytesCapTooSmall {
                per_entry: self.max_uncompressed_bytes_per_entry,
                per_archive: self.max_total_uncompressed_bytes_per_archive,
            });
        }
        if self.max_total_uncompressed_bytes_per_root
            < self.max_total_uncompressed_bytes_per_archive
        {
            return Err(ArchiveConfigError::RootBytesCapTooSmall {
                per_archive: self.max_total_uncompressed_bytes_per_archive,
                per_root: self.max_total_uncompressed_bytes_per_root,
            });
        }
        if self.max_archive_metadata_bytes == 0 {
            return Err(ArchiveConfigError::MaxArchiveMetadataBytesZero);
        }
        if self.max_inflation_ratio == 0 {
            return Err(ArchiveConfigError::MaxInflationRatioZero);
        }
        if self.max_virtual_path_len_per_entry == 0 {
            return Err(ArchiveConfigError::MaxVirtualPathLenPerEntryZero);
        }
        if self.max_virtual_path_bytes_per_archive == 0 {
            return Err(ArchiveConfigError::MaxVirtualPathBytesPerArchiveZero);
        }
        if self.max_virtual_path_bytes_per_archive < self.max_virtual_path_len_per_entry {
            return Err(ArchiveConfigError::PathBudgetTooSmall {
                per_entry: self.max_virtual_path_len_per_entry,
                per_archive: self.max_virtual_path_bytes_per_archive,
            });
        }
        if let Some(secs) = self.max_wall_clock_secs_per_root {
            if secs == 0 {
                return Err(ArchiveConfigError::MaxWallClockSecsPerRootZero);
            }
            if secs > MAX_WALL_CLOCK_SECS_PER_ROOT {
                return Err(ArchiveConfigError::MaxWallClockSecsPerRootTooLarge {
                    value: secs,
                    max: MAX_WALL_CLOCK_SECS_PER_ROOT,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_and_sane() {
        let cfg = ArchiveConfig::default();
        assert!(cfg.enabled);
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_inconsistent_byte_caps() {
        let cfg = ArchiveConfig {
            max_total_uncompressed_bytes_per_archive: 1,
            max_uncompressed_bytes_per_entry: 2,
            ..ArchiveConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(
            err,
            ArchiveConfigError::ArchiveBytesCapTooSmall { .. }
        ));
    }

    #[test]
    fn default_wall_clock_is_none() {
        let cfg = ArchiveConfig::default();
        assert_eq!(cfg.max_wall_clock_secs_per_root, None);
    }

    #[test]
    fn validate_rejects_zero_wall_clock() {
        let cfg = ArchiveConfig {
            max_wall_clock_secs_per_root: Some(0),
            ..ArchiveConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(
            err,
            ArchiveConfigError::MaxWallClockSecsPerRootZero
        ));
    }

    #[test]
    fn validate_accepts_nonzero_wall_clock() {
        let cfg = ArchiveConfig {
            max_wall_clock_secs_per_root: Some(30),
            ..ArchiveConfig::default()
        };
        cfg.validate().unwrap();
    }

    #[test]
    fn validate_rejects_excessive_wall_clock() {
        let cfg = ArchiveConfig {
            max_wall_clock_secs_per_root: Some(MAX_WALL_CLOCK_SECS_PER_ROOT + 1),
            ..ArchiveConfig::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(
            err,
            ArchiveConfigError::MaxWallClockSecsPerRootTooLarge { .. }
        ));
    }

    #[test]
    fn validate_accepts_max_wall_clock_boundary() {
        let cfg = ArchiveConfig {
            max_wall_clock_secs_per_root: Some(MAX_WALL_CLOCK_SECS_PER_ROOT),
            ..ArchiveConfig::default()
        };
        cfg.validate().unwrap();
    }
}
