//! Hard caps and tunables for Git maintenance preflight.
//!
//! All limits are explicit and enforced for file reads. Pack count is tracked
//! as a maintenance recommendation threshold, not a hard gate. These bounds
//! keep preflight fast and deterministic by capping file reads and the
//! maximum number of pack files inspected across object stores.
//!
//! # Invariants
//! - Limits are validated in const contexts; callers may invoke `validate()` explicitly.
//! - Pack count thresholds are advisory; readiness is determined elsewhere.

/// Hard caps for maintenance preflight.
///
/// These limits bound file reads during repository discovery and provide
/// pack-count thresholds for maintenance recommendations.
#[derive(Clone, Copy, Debug)]
pub struct PreflightLimits {
    /// Pack count recommendation threshold across all object stores.
    ///
    /// Pack files are counted by `*.pack` entries in `objects/pack`, including
    /// alternate object directories. Default: 4 (target 1-4 packs).
    pub max_pack_count: u16,

    /// Maximum bytes to read from `.git` file (gitdir pointer).
    ///
    /// Contains only `gitdir: <path>`. 8 KB is generous.
    pub max_dot_git_file_bytes: u32,

    /// Maximum bytes to read from `commondir` file.
    ///
    /// Contains a relative or absolute path.
    pub max_commondir_file_bytes: u32,

    /// Maximum bytes to read from `info/alternates` file.
    ///
    /// One path per line; large repos may have several alternates.
    pub max_alternates_file_bytes: u32,

    /// Maximum number of alternate object directories.
    ///
    /// Alternates are relatively rare; a few is typical.
    pub max_alternates_count: u8,
}

impl PreflightLimits {
    /// Safe defaults suitable for large monorepos.
    ///
    /// These values trade a small amount of metadata IO for predictable
    /// preflight performance on large repositories.
    pub const DEFAULT: Self = Self {
        max_pack_count: 4,
        max_dot_git_file_bytes: 8 * 1024,
        max_commondir_file_bytes: 8 * 1024,
        max_alternates_file_bytes: 64 * 1024,
        max_alternates_count: 16,
    };

    /// Restrictive limits for testing or constrained environments.
    pub const RESTRICTIVE: Self = Self {
        max_pack_count: 1,
        max_dot_git_file_bytes: 1024,
        max_commondir_file_bytes: 1024,
        max_alternates_file_bytes: 4 * 1024,
        max_alternates_count: 4,
    };

    /// Validates that limits are internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (indicates a configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        assert!(self.max_pack_count > 0, "max_pack_count must be > 0");
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
            self.max_pack_count <= 1024,
            "unreasonably large pack count limit"
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
    }
}

impl Default for PreflightLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl super::repo::RepoLimits for PreflightLimits {
    fn max_dot_git_file_bytes(&self) -> u32 {
        self.max_dot_git_file_bytes
    }

    fn max_commondir_file_bytes(&self) -> u32 {
        self.max_commondir_file_bytes
    }

    fn max_alternates_file_bytes(&self) -> u32 {
        self.max_alternates_file_bytes
    }

    fn max_alternates_count(&self) -> u8 {
        self.max_alternates_count
    }
}

// Compile-time validation of default limits.
const _: () = PreflightLimits::DEFAULT.validate();
const _: () = PreflightLimits::RESTRICTIVE.validate();

// Compile-time size assertion (verify packed layout).
const _: () = assert!(std::mem::size_of::<PreflightLimits>() <= 24);
