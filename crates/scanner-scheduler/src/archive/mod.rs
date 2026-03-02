//! Archive scanning support modules.
//!
//! # Scope
//! This module defines the public contract for archive handling:
//! configuration, outcomes, deterministic budgets, path canonicalization,
//! and format-specific helpers.
//!
//! # Design Notes
//! - Scanners are streaming-only and bounded by `ArchiveConfig` caps.
//! - Outcomes and reason enums are stable, indexable, and allocation-free.

pub mod budget;
pub mod config;
pub mod detect;
pub mod formats;
pub mod outcome;
pub mod path;
pub mod scan;
pub(crate) mod util;

pub use budget::{ArchiveBudgets, BudgetHit, ChargeResult};
pub use config::{
    ArchiveConfig, ArchiveConfigError, EncryptedPolicy, UnsupportedPolicy,
    DEFAULT_WALL_CLOCK_SECS_PER_ROOT, MAX_WALL_CLOCK_SECS_PER_ROOT,
};
pub use detect::{
    detect_kind, detect_kind_from_name, detect_kind_from_name_bytes, detect_kind_from_path,
    sniff_kind_from_header, ArchiveKind,
};
pub use outcome::{
    ArchiveSample, ArchiveSampleRing, ArchiveSkipReason, ArchiveStats, EntrySkipReason,
    PartialReason, SampleKind, ARCHIVE_SAMPLE_MAX, ARCHIVE_SAMPLE_PATH_PREFIX_MAX,
};
pub use path::{
    CanonicalPath, EntryPathCanonicalizer, VirtualPath, VirtualPathBuilder, DEFAULT_MAX_COMPONENTS,
};
pub use scan::{
    scan_bzip2_stream, scan_gzip_stream, scan_tar_stream, scan_tarbz2_stream, scan_targz_stream,
    scan_zip_source, ArchiveEnd, ArchiveEntrySink, ArchiveScratch, EntryChunk, EntryMeta,
};
