//! Hard caps and tunables for spill + dedupe.
//!
//! These limits bound in-memory spill chunk size and on-disk spill growth.
//! They are enforced explicitly to keep spill behavior deterministic and
//! resource usage predictable. All byte-related fields are expressed in
//! raw bytes (not KiB/MiB).

/// Hard caps for spill chunking, run management, and seen-store batching.
///
/// # Layout
/// Fields ordered for alignment (largest first).
/// Size: 32 bytes (verified at compile time).
#[derive(Clone, Copy, Debug)]
pub struct SpillLimits {
    /// Maximum total bytes for spill runs on disk.
    ///
    /// Default: 64 GB.
    pub max_spill_bytes: u64,

    /// Maximum OIDs per seen-store batch query.
    ///
    /// Default: 8,192.
    pub seen_batch_max_oids: u32,

    /// Maximum bytes for the seen-store batch path arena.
    ///
    /// Default: 512 KB.
    pub seen_batch_max_path_bytes: u32,

    /// Maximum candidates per in-memory chunk.
    ///
    /// Default: 1,048,576 (1M candidates).
    pub max_chunk_candidates: u32,

    /// Maximum bytes for the chunk's path arena.
    ///
    /// Default: 64 MB.
    pub max_chunk_path_bytes: u32,

    /// Maximum spill runs permitted.
    ///
    /// Default: 128.
    pub max_spill_runs: u16,

    /// Maximum path length allowed in spill records.
    ///
    /// Default: 8 KiB (2× tree diff path cap of 4 KiB).
    pub max_path_len: u16,
}

impl SpillLimits {
    /// Safe defaults for large repositories.
    ///
    /// Chosen to favor throughput while staying within reasonable memory
    /// and spill growth bounds.
    pub const DEFAULT: Self = Self {
        max_spill_bytes: 64 * 1024 * 1024 * 1024, // 64 GB
        seen_batch_max_oids: 8_192,
        seen_batch_max_path_bytes: 512 * 1024, // 512 KB
        max_chunk_candidates: 1_048_576,
        max_chunk_path_bytes: 64 * 1024 * 1024, // 64 MB
        max_spill_runs: 128,
        max_path_len: 8 * 1024,
    };

    /// Restrictive defaults for tests or constrained environments.
    ///
    /// Lower caps reduce memory usage at the cost of more spill runs.
    pub const RESTRICTIVE: Self = Self {
        max_spill_bytes: 512 * 1024 * 1024, // 512 MB
        seen_batch_max_oids: 256,
        seen_batch_max_path_bytes: 64 * 1024, // 64 KB
        max_chunk_candidates: 16_384,
        max_chunk_path_bytes: 1024 * 1024, // 1 MB
        max_spill_runs: 16,
        max_path_len: 4 * 1024,
    };

    /// Validates that limits are internally consistent.
    ///
    /// This enforces both non-zero values and hard upper bounds intended
    /// to catch configuration mistakes.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        assert!(self.max_spill_bytes > 0, "spill bytes must be > 0");
        assert!(
            self.max_chunk_candidates > 0,
            "must allow at least 1 candidate"
        );
        assert!(self.max_chunk_path_bytes > 0, "path arena must be > 0");
        assert!(
            self.seen_batch_max_oids > 0,
            "must allow at least 1 seen batch OID"
        );
        assert!(
            self.seen_batch_max_path_bytes > 0,
            "seen batch path arena must be > 0"
        );
        assert!(self.max_spill_runs > 0, "must allow at least 1 spill run");
        assert!(self.max_path_len > 0, "path length must be > 0");
        assert!(
            self.seen_batch_max_path_bytes >= self.max_path_len as u32,
            "seen batch path arena must fit max path length"
        );

        assert!(
            self.max_chunk_candidates <= 100_000_000,
            "candidate limit > 100M is unreasonable"
        );
        assert!(
            self.max_chunk_path_bytes <= 1024 * 1024 * 1024,
            "path arena > 1GB is unreasonable"
        );
        assert!(
            self.seen_batch_max_oids <= 1_000_000,
            "seen batch OID cap > 1M is unreasonable"
        );
        assert!(
            self.seen_batch_max_path_bytes <= 64 * 1024 * 1024,
            "seen batch path arena > 64MB is unreasonable"
        );
        assert!(
            self.max_spill_bytes <= 2 * 1024 * 1024 * 1024 * 1024_u64,
            "spill bytes > 2TB is unreasonable"
        );
    }

    /// Non-panicking validation for runtime configuration.
    ///
    /// Returns a short static error string suitable for configuration errors.
    pub const fn try_validate(&self) -> Result<(), &'static str> {
        if self.max_spill_bytes == 0 {
            return Err("spill bytes must be > 0");
        }
        if self.max_chunk_candidates == 0 {
            return Err("must allow at least 1 candidate");
        }
        if self.max_chunk_path_bytes == 0 {
            return Err("path arena must be > 0");
        }
        if self.seen_batch_max_oids == 0 {
            return Err("must allow at least 1 seen batch OID");
        }
        if self.seen_batch_max_path_bytes == 0 {
            return Err("seen batch path arena must be > 0");
        }
        if self.max_spill_runs == 0 {
            return Err("must allow at least 1 spill run");
        }
        if self.max_path_len == 0 {
            return Err("path length must be > 0");
        }
        if self.seen_batch_max_path_bytes < self.max_path_len as u32 {
            return Err("seen batch path arena must fit max path length");
        }
        if self.max_chunk_candidates > 100_000_000 {
            return Err("candidate limit > 100M is unreasonable");
        }
        if self.max_chunk_path_bytes > 1024 * 1024 * 1024 {
            return Err("path arena > 1GB is unreasonable");
        }
        if self.seen_batch_max_oids > 1_000_000 {
            return Err("seen batch OID cap > 1M is unreasonable");
        }
        if self.seen_batch_max_path_bytes > 64 * 1024 * 1024 {
            return Err("seen batch path arena > 64MB is unreasonable");
        }
        if self.max_spill_bytes > 2 * 1024 * 1024 * 1024 * 1024_u64 {
            return Err("spill bytes > 2TB is unreasonable");
        }
        Ok(())
    }
}

impl Default for SpillLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _: () = SpillLimits::DEFAULT.validate();
const _: () = SpillLimits::RESTRICTIVE.validate();
// Keep the struct layout fixed for predictable serialization/caching costs.
const _: () = assert!(std::mem::size_of::<SpillLimits>() == 32);
