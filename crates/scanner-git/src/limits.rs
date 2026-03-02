//! Hard caps and tunables for repo discovery and open.
//!
//! These limits are guardrails against unbounded metadata reads and
//! allocations during repo discovery. All limits are explicit and enforced;
//! exceeding a limit generally surfaces as an error, though some bounds
//! (e.g. `max_alternates_count`) silently truncate excess entries.
//!
//! # Design Notes
//! - Limits are validated at startup; invalid configurations are treated
//!   as programmer errors (panic in `validate`).
//! - Defaults favor large monorepos while staying within sensible memory bounds.

/// Hard caps for repository discovery and open.
///
/// Repo discovery only inspects repository metadata; these limits bound
/// the size of that metadata so the scan remains predictable and cheap.
#[derive(Clone, Copy, Debug)]
pub struct RepoOpenLimits {
    // --- u32 fields (grouped for alignment) ---
    /// Maximum number of refs in the start set (refs selected for scanning).
    pub max_refs_in_start_set: u32,

    /// Maximum total bytes for the ref name arena.
    ///
    /// This bounds the total memory reserved for storing ref names and
    /// should be sized to hold all refs in the start set.
    pub max_refname_arena_bytes: u32,

    /// Maximum bytes to read from `.git` file (gitdir pointer).
    pub max_dot_git_file_bytes: u32,

    /// Maximum bytes to read from `commondir` file.
    pub max_commondir_file_bytes: u32,

    /// Maximum bytes to read from `info/alternates` file.
    pub max_alternates_file_bytes: u32,

    /// Maximum bytes to read from repository config.
    pub max_config_file_bytes: u32,

    // --- u16 fields ---
    /// Maximum length of a single ref name in bytes.
    pub max_refname_bytes: u16,

    // --- u8 fields ---
    /// Maximum number of alternate object directories.
    ///
    /// Alternates are rare in most repos; this caps pathological cases.
    pub max_alternates_count: u8,
}

impl RepoOpenLimits {
    /// Safe defaults suitable for large monorepos.
    pub const DEFAULT: Self = Self {
        max_refs_in_start_set: 16_384,
        max_refname_bytes: 1024,
        max_refname_arena_bytes: 4 * 1024 * 1024,
        max_dot_git_file_bytes: 8 * 1024,
        max_commondir_file_bytes: 8 * 1024,
        max_alternates_file_bytes: 64 * 1024,
        max_config_file_bytes: 128 * 1024,
        max_alternates_count: 16,
    };

    /// Restrictive limits for testing or constrained environments.
    pub const RESTRICTIVE: Self = Self {
        max_refs_in_start_set: 256,
        max_refname_bytes: 256,
        max_refname_arena_bytes: 64 * 1024,
        max_dot_git_file_bytes: 1024,
        max_commondir_file_bytes: 1024,
        max_alternates_file_bytes: 4 * 1024,
        max_config_file_bytes: 8 * 1024,
        max_alternates_count: 4,
    };

    /// Validates that limits are internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (indicates a configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        assert!(self.max_refs_in_start_set > 0, "must allow at least 1 ref");
        assert!(self.max_refname_bytes > 0, "must allow non-empty refs");
        assert!(
            self.max_alternates_count > 0,
            "must allow at least 1 alternate"
        );

        assert!(
            self.max_dot_git_file_bytes > 0,
            "dot-git file limit must be > 0"
        );
        assert!(
            self.max_commondir_file_bytes > 0,
            "commondir file limit must be > 0"
        );
        assert!(
            self.max_alternates_file_bytes > 0,
            "alternates file limit must be > 0"
        );
        assert!(
            self.max_config_file_bytes > 0,
            "config file limit must be > 0"
        );

        assert!(
            self.max_refname_arena_bytes >= self.max_refname_bytes as u32,
            "arena too small for single ref"
        );
        assert!(
            self.max_refname_arena_bytes >= self.max_refs_in_start_set,
            "arena too small for ref count (need at least 1 byte per ref)"
        );

        assert!(
            self.max_refs_in_start_set <= 1_000_000,
            "unreasonably large ref limit (start set, not total refs)"
        );
        assert!(
            self.max_refname_arena_bytes <= 1024 * 1024 * 1024,
            "unreasonably large arena"
        );
        assert!(
            self.max_dot_git_file_bytes <= 1024 * 1024,
            "dot-git file limit too large"
        );
        assert!(
            self.max_commondir_file_bytes <= 1024 * 1024,
            "commondir file limit too large"
        );
        assert!(
            self.max_alternates_file_bytes <= 16 * 1024 * 1024,
            "alternates file limit too large"
        );
        assert!(
            self.max_config_file_bytes <= 16 * 1024 * 1024,
            "config file limit too large"
        );
    }
}

impl Default for RepoOpenLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _: () = RepoOpenLimits::DEFAULT.validate();
const _: () = RepoOpenLimits::RESTRICTIVE.validate();
const _: () = assert!(std::mem::size_of::<RepoOpenLimits>() == 28);
