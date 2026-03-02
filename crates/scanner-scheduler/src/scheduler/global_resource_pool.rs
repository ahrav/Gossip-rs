//! Global Resource Pool for Fat Jobs
//!
//! # Purpose
//!
//! Provides global resource reservation for "fat" jobs that require significant
//! memory beyond per-object tracking. Examples:
//!
//! - Git repository scanning (scan ring + delta cache)
//! - Large archive extraction (decompression buffers)
//! - Multi-file container scanning (ZIP, TAR)
//!
//! # Problem Solved
//!
//! Per-object budgets (`ObjectFrontier`) don't prevent N concurrent repo jobs
//! from each independently claiming B+D bytes. This module ensures the scheduler's
//! "hard caps" invariant holds at the global level.
//!
//! # Architecture
//!
//! ```text
//! GlobalResourcePool::try_acquire_fat_job_permit()  ← caps total memory
//!     └── repo scan starts
//!         └── ObjectFrontier::try_acquire_ctx()  ← caps concurrent blobs
//! ```
//!
//! # Correctness Invariants
//!
//! - **All-or-nothing**: Partial acquisition never occurs (prevents deadlock)
//! - **Fixed acquisition order**: Consistent ordering for code clarity
//! - **Leak-free**: `FatJobPermit` releases all sub-permits via RAII Drop
//! - **Bounded**: Total memory across all fat jobs never exceeds configured limits
//!
//! # Performance Characteristics
//!
//! | Operation | Cost |
//! |-----------|------|
//! | try_acquire_fat_job_permit | 2-3 atomic CAS operations |
//! | release (Drop) | 2-3 atomic releases |
//!
//! This is appropriate for job-level backpressure (tens/sec), not object-level.
//!
//! # Known Limitations
//!
//! - **No fairness guarantee**: Large jobs may be starved by streams of small jobs
//!   that keep resources just below the large job's threshold. The scheduler should
//!   implement backoff for failed large-job acquisitions.
//! - **No wait queue**: Jobs that fail to acquire must re-enqueue themselves.
//!   This is consistent with the existing `ObjectFrontier` pattern.

use std::sync::Arc;

use super::budget::ByteBudget;
use super::count_budget::{CountBudget, CountPermit};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for global resource pools.
///
/// # Sizing Guidelines
///
/// - `scan_ring_bytes`: Total across all concurrent fat jobs. Each Git repo
///   needs ~10-50MB depending on commit graph complexity.
/// - `delta_cache_bytes`: For Git delta resolution. ~25-100MB per repo typical.
/// - `spill_slots`: Limits concurrent disk-spilling operations. Optional.
///
/// # Example
///
/// For a system scanning up to 4 Git repos concurrently with ~50MB each:
/// ```ignore
/// let config = GlobalResourcePoolConfig {
///     scan_ring_bytes: 200_000_000,   // 200MB total
///     delta_cache_bytes: 400_000_000, // 400MB total
///     spill_slots: Some(8),           // 8 concurrent spill ops
/// };
/// ```
///
/// # Note on Units
///
/// All byte fields are in **bytes**, not megabytes. Use the helper methods
/// on `FatJobRequest` (e.g., `git_repo(mb, mb, bool)`) for convenience.
#[derive(Clone, Debug)]
pub struct GlobalResourcePoolConfig {
    /// Total bytes available for scan rings across all fat jobs.
    pub scan_ring_bytes: u64,

    /// Total bytes available for delta/decompression caches.
    pub delta_cache_bytes: u64,

    /// Optional: limit concurrent disk-spilling operations.
    /// `None` means no limit on spill concurrency (unlimited).
    pub spill_slots: Option<usize>,
}

impl Default for GlobalResourcePoolConfig {
    fn default() -> Self {
        Self {
            // Conservative defaults for a typical CI runner
            scan_ring_bytes: 256 * 1024 * 1024,   // 256 MB
            delta_cache_bytes: 512 * 1024 * 1024, // 512 MB
            spill_slots: Some(16),
        }
    }
}

impl GlobalResourcePoolConfig {
    /// Validate configuration.
    ///
    /// # Panics
    ///
    /// Panics if configuration is invalid.
    pub fn validate(&self) {
        assert!(self.scan_ring_bytes > 0, "scan_ring_bytes must be > 0");
        assert!(self.delta_cache_bytes > 0, "delta_cache_bytes must be > 0");
        if let Some(slots) = self.spill_slots {
            assert!(slots > 0, "spill_slots must be > 0 if specified");
        }
    }
}

// ============================================================================
// SpillGrant - Explicit spill permission semantics
// ============================================================================

/// Represents the granted spill permission.
///
/// This enum makes spill semantics explicit rather than inferring from
/// `Option<CountPermit>` presence.
#[derive(Debug)]
enum SpillGrant {
    /// Spilling was not requested by the job.
    NotRequested,
    /// Spilling is unlimited (no slots configured in pool).
    Unlimited,
    /// Spilling is permitted via a counted slot.
    Limited { _permit: CountPermit },
}

impl SpillGrant {
    /// Whether spilling is allowed (either unlimited or slot acquired).
    #[inline]
    fn is_allowed(&self) -> bool {
        matches!(self, SpillGrant::Unlimited | SpillGrant::Limited { .. })
    }

    /// Whether spilling is governed by a counted slot.
    #[inline]
    fn is_limited(&self) -> bool {
        matches!(self, SpillGrant::Limited { .. })
    }
}

// ============================================================================
// GlobalResourcePool
// ============================================================================

/// Global resource pools for fat jobs (Git repos, large archives).
///
/// # Thread Safety
///
/// Safe to share via `Arc<GlobalResourcePool>`. All internal budgets are
/// thread-safe.
///
/// # Usage
///
/// ```ignore
/// let pool = GlobalResourcePool::new(config);
///
/// // Before starting a Git repo scan
/// let permit = pool.try_acquire_fat_job_permit(
///     FatJobRequest {
///         scan_ring_bytes: 50_000_000,
///         delta_cache_bytes: 100_000_000,
///         needs_spill_slot: true,
///     }
/// );
///
/// match permit {
///     Some(p) => {
///         // Proceed with repo scan
///         scan_repo(repo, p);
///         // Permit automatically released when dropped
///     }
///     None => {
///         // Re-enqueue for later
///         requeue_enumerate_task();
///     }
/// }
/// ```
#[derive(Debug)]
pub struct GlobalResourcePool {
    /// Budget for scan ring memory.
    scan_ring: Arc<ByteBudget>,

    /// Budget for delta/decompression cache memory.
    delta_cache: Arc<ByteBudget>,

    /// Optional budget for concurrent spill operations.
    spill_slots: Option<Arc<CountBudget>>,
}

impl GlobalResourcePool {
    /// Create a new global resource pool with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if configuration is invalid (see `GlobalResourcePoolConfig::validate`).
    pub fn new(config: GlobalResourcePoolConfig) -> Arc<Self> {
        config.validate();

        Arc::new(Self {
            scan_ring: Arc::new(ByteBudget::new(config.scan_ring_bytes)),
            delta_cache: Arc::new(ByteBudget::new(config.delta_cache_bytes)),
            spill_slots: config.spill_slots.map(CountBudget::new),
        })
    }

    /// Create a pool with explicit budgets (for testing).
    #[cfg(test)]
    pub fn from_budgets(
        scan_ring: Arc<ByteBudget>,
        delta_cache: Arc<ByteBudget>,
        spill_slots: Option<Arc<CountBudget>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            scan_ring,
            delta_cache,
            spill_slots,
        })
    }

    /// Try to acquire all resources for a fat job.
    ///
    /// Returns `None` if ANY requested resource is unavailable. This is
    /// all-or-nothing to prevent partial allocation deadlock.
    ///
    /// # Acquisition Order
    ///
    /// Resources are acquired in a fixed order for consistency:
    /// 1. Scan ring bytes
    /// 2. Delta cache bytes
    /// 3. Spill slot (if requested)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let permit = pool.try_acquire_fat_job_permit(FatJobRequest {
    ///     scan_ring_bytes: 50_000_000,
    ///     delta_cache_bytes: 100_000_000,
    ///     needs_spill_slot: false,
    /// });
    /// ```
    pub fn try_acquire_fat_job_permit(
        self: &Arc<Self>,
        request: FatJobRequest,
    ) -> Option<FatJobPermit> {
        // Check for truly empty request (no bytes AND no spill)
        // IMPORTANT: Do NOT short-circuit if needs_spill_slot is true!
        if request.scan_ring_bytes == 0
            && request.delta_cache_bytes == 0
            && !request.needs_spill_slot
        {
            return Some(FatJobPermit {
                pool: Arc::clone(self),
                scan_ring_bytes: 0,
                delta_cache_bytes: 0,
                spill_grant: SpillGrant::NotRequested,
            });
        }

        // Step 1: Acquire scan ring bytes
        let scan_ring_amount = if request.scan_ring_bytes > 0 {
            match self.scan_ring.try_acquire(request.scan_ring_bytes) {
                Some(permit) => permit.into_raw(), // Detach from RAII for manual management
                None => return None,
            }
        } else {
            0
        };

        // Step 2: Acquire delta cache bytes
        let delta_cache_amount = if request.delta_cache_bytes > 0 {
            match self.delta_cache.try_acquire(request.delta_cache_bytes) {
                Some(permit) => permit.into_raw(),
                None => {
                    // Rollback step 1
                    if scan_ring_amount > 0 {
                        self.scan_ring.release_raw(scan_ring_amount);
                    }
                    return None;
                }
            }
        } else {
            0
        };

        // Step 3: Acquire spill slot (if requested)
        let spill_grant = if request.needs_spill_slot {
            match &self.spill_slots {
                Some(budget) => {
                    match budget.try_acquire(1) {
                        Some(permit) => SpillGrant::Limited { _permit: permit },
                        None => {
                            // Rollback steps 1 and 2
                            if delta_cache_amount > 0 {
                                self.delta_cache.release_raw(delta_cache_amount);
                            }
                            if scan_ring_amount > 0 {
                                self.scan_ring.release_raw(scan_ring_amount);
                            }
                            return None;
                        }
                    }
                }
                None => {
                    // No spill slots configured - spilling is unlimited
                    SpillGrant::Unlimited
                }
            }
        } else {
            SpillGrant::NotRequested
        };

        Some(FatJobPermit {
            pool: Arc::clone(self),
            scan_ring_bytes: scan_ring_amount,
            delta_cache_bytes: delta_cache_amount,
            spill_grant,
        })
    }

    /// Available scan ring bytes.
    #[inline]
    pub fn scan_ring_available(&self) -> u64 {
        self.scan_ring.available()
    }

    /// Total scan ring capacity.
    #[inline]
    pub fn scan_ring_total(&self) -> u64 {
        self.scan_ring.total()
    }

    /// Available delta cache bytes.
    #[inline]
    pub fn delta_cache_available(&self) -> u64 {
        self.delta_cache.available()
    }

    /// Total delta cache capacity.
    #[inline]
    pub fn delta_cache_total(&self) -> u64 {
        self.delta_cache.total()
    }

    /// Available spill slots (None if unlimited).
    #[inline]
    pub fn spill_slots_available(&self) -> Option<usize> {
        self.spill_slots.as_ref().map(|b| b.available())
    }

    /// Total spill slots (None if unlimited).
    #[inline]
    pub fn spill_slots_total(&self) -> Option<usize> {
        self.spill_slots.as_ref().map(|b| b.total())
    }

    /// Internal: release scan ring bytes (used by FatJobPermit::Drop)
    fn release_scan_ring(&self, bytes: u64) {
        if bytes > 0 {
            self.scan_ring.release_raw(bytes);
        }
    }

    /// Internal: release delta cache bytes (used by FatJobPermit::Drop)
    fn release_delta_cache(&self, bytes: u64) {
        if bytes > 0 {
            self.delta_cache.release_raw(bytes);
        }
    }
}

// ============================================================================
// FatJobRequest
// ============================================================================

/// Resource request for a fat job.
///
/// # Sizing Guidelines
///
/// For Git repositories:
/// - `scan_ring_bytes`: 10-50 MB typical, depends on commit graph traversal depth
/// - `delta_cache_bytes`: 25-100 MB typical, depends on pack file complexity
/// - `needs_spill_slot`: true if candidate buffer may spill to disk
///
/// For archives (ZIP, TAR):
/// - `scan_ring_bytes`: Size of largest expected file in archive
/// - `delta_cache_bytes`: 0 (no delta resolution)
/// - `needs_spill_slot`: true if extraction may need temp files
#[derive(Clone, Copy, Debug, Default)]
pub struct FatJobRequest {
    /// Bytes needed for scan ring.
    pub scan_ring_bytes: u64,

    /// Bytes needed for delta/decompression cache.
    pub delta_cache_bytes: u64,

    /// Whether this job may spill to disk.
    pub needs_spill_slot: bool,
}

impl FatJobRequest {
    /// Create a request for a Git repository scan.
    ///
    /// # Parameters
    ///
    /// - `scan_ring_mb`: Scan ring size in **megabytes**
    /// - `delta_cache_mb`: Delta cache size in **megabytes**
    /// - `needs_spill`: Whether candidate buffer may spill
    ///
    /// # Panics
    ///
    /// Panics if the MB values would overflow when converted to bytes.
    pub fn git_repo(scan_ring_mb: u64, delta_cache_mb: u64, needs_spill: bool) -> Self {
        const MB: u64 = 1024 * 1024;

        let scan_ring_bytes = scan_ring_mb
            .checked_mul(MB)
            .expect("scan_ring_mb overflow: value too large");

        let delta_cache_bytes = delta_cache_mb
            .checked_mul(MB)
            .expect("delta_cache_mb overflow: value too large");

        Self {
            scan_ring_bytes,
            delta_cache_bytes,
            needs_spill_slot: needs_spill,
        }
    }

    /// Create a request for archive extraction.
    pub fn archive(max_file_size: u64, needs_spill: bool) -> Self {
        Self {
            scan_ring_bytes: max_file_size,
            delta_cache_bytes: 0,
            needs_spill_slot: needs_spill,
        }
    }
}

// ============================================================================
// FatJobPermit
// ============================================================================

/// RAII permit for a fat job's global resources.
///
/// # Lifetime
///
/// The permit must be held for the entire duration of the fat job. When dropped,
/// all reserved resources are released back to the global pool.
///
/// # Typical Pattern
///
/// ```ignore
/// struct GitRepoJob {
///     permit: FatJobPermit,
///     // ... other job state ...
/// }
///
/// impl Drop for GitRepoJob {
///     fn drop(&mut self) {
///         // permit automatically released here
///     }
/// }
/// ```
///
/// # Cancel Safety
///
/// If a job is cancelled mid-execution, simply dropping the permit ensures
/// all resources are returned. No manual cleanup required.
#[derive(Debug)]
#[must_use = "FatJobPermit releases resources on drop; not holding it defeats backpressure"]
pub struct FatJobPermit {
    /// Reference to pool for release on drop.
    pool: Arc<GlobalResourcePool>,

    /// Scan ring bytes held (released on drop via pool).
    scan_ring_bytes: u64,

    /// Delta cache bytes held (released on drop via pool).
    delta_cache_bytes: u64,

    /// Spill permission grant.
    spill_grant: SpillGrant,
}

impl FatJobPermit {
    /// Bytes reserved for scan ring.
    #[inline]
    pub fn scan_ring_bytes(&self) -> u64 {
        self.scan_ring_bytes
    }

    /// Bytes reserved for delta cache.
    #[inline]
    pub fn delta_cache_bytes(&self) -> u64 {
        self.delta_cache_bytes
    }

    /// Whether this permit allows spilling to disk.
    ///
    /// Returns `true` if:
    /// - A spill slot was explicitly acquired (limited mode), OR
    /// - Spilling is unlimited (no slots configured in pool)
    ///
    /// Returns `false` only if spilling was not requested.
    #[inline]
    pub fn can_spill(&self) -> bool {
        self.spill_grant.is_allowed()
    }

    /// Whether spill concurrency is governed by a counted slot.
    ///
    /// Returns `true` only if a limited spill slot was acquired.
    /// Returns `false` if spilling is unlimited or was not requested.
    #[inline]
    pub fn spill_is_limited(&self) -> bool {
        self.spill_grant.is_limited()
    }

    /// Total bytes reserved (scan ring + delta cache).
    ///
    /// # Panics
    ///
    /// Panics in debug builds if the sum overflows (indicates a bug in
    /// permit construction or configuration).
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        let total = self.scan_ring_bytes.saturating_add(self.delta_cache_bytes);
        debug_assert!(
            self.scan_ring_bytes
                .checked_add(self.delta_cache_bytes)
                .is_some(),
            "total_bytes overflow: scan={} + delta={} overflows u64",
            self.scan_ring_bytes,
            self.delta_cache_bytes
        );
        total
    }
}

impl Drop for FatJobPermit {
    fn drop(&mut self) {
        // Tiger Style: Debug assertions to catch double-release or corruption
        debug_assert!(
            self.scan_ring_bytes <= self.pool.scan_ring.total(),
            "FatJobPermit::drop: scan_ring_bytes {} exceeds pool total {} (double release?)",
            self.scan_ring_bytes,
            self.pool.scan_ring.total()
        );
        debug_assert!(
            self.delta_cache_bytes <= self.pool.delta_cache.total(),
            "FatJobPermit::drop: delta_cache_bytes {} exceeds pool total {} (double release?)",
            self.delta_cache_bytes,
            self.pool.delta_cache.total()
        );

        // Release byte budgets manually (we used into_raw() on acquisition)
        self.pool.release_scan_ring(self.scan_ring_bytes);
        self.pool.release_delta_cache(self.delta_cache_bytes);

        // Spill slot is released automatically by SpillGrant::Limited's CountPermit Drop
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> GlobalResourcePoolConfig {
        GlobalResourcePoolConfig {
            scan_ring_bytes: 100_000_000,   // 100 MB
            delta_cache_bytes: 200_000_000, // 200 MB
            spill_slots: Some(4),
        }
    }

    #[test]
    fn basic_acquisition_and_release() {
        let pool = GlobalResourcePool::new(test_config());

        let request = FatJobRequest {
            scan_ring_bytes: 50_000_000,
            delta_cache_bytes: 100_000_000,
            needs_spill_slot: true,
        };

        // Acquire
        let permit = pool.try_acquire_fat_job_permit(request);
        assert!(permit.is_some());

        let permit = permit.unwrap();
        assert_eq!(permit.scan_ring_bytes(), 50_000_000);
        assert_eq!(permit.delta_cache_bytes(), 100_000_000);
        assert!(permit.can_spill());
        assert!(permit.spill_is_limited());

        // Verify resources are reserved
        assert_eq!(pool.scan_ring_available(), 50_000_000);
        assert_eq!(pool.delta_cache_available(), 100_000_000);
        assert_eq!(pool.spill_slots_available(), Some(3));

        // Release
        drop(permit);

        // Verify resources are returned
        assert_eq!(pool.scan_ring_available(), 100_000_000);
        assert_eq!(pool.delta_cache_available(), 200_000_000);
        assert_eq!(pool.spill_slots_available(), Some(4));
    }

    #[test]
    fn global_pool_prevents_over_commit() {
        let pool = GlobalResourcePool::new(test_config());

        // Each request wants 60MB scan ring (only 100MB total)
        let request = FatJobRequest {
            scan_ring_bytes: 60_000_000,
            delta_cache_bytes: 50_000_000,
            needs_spill_slot: false,
        };

        let p1 = pool.try_acquire_fat_job_permit(request);
        assert!(p1.is_some());

        let p2 = pool.try_acquire_fat_job_permit(request);
        assert!(
            p2.is_none(),
            "second request should fail (only 40MB remaining)"
        );

        // After releasing first, second should succeed
        drop(p1);

        let p2 = pool.try_acquire_fat_job_permit(request);
        assert!(p2.is_some());
    }

    #[test]
    fn partial_acquisition_releases_all() {
        let config = GlobalResourcePoolConfig {
            scan_ring_bytes: 100_000_000,
            delta_cache_bytes: 10_000_000, // Only 10MB delta
            spill_slots: Some(4),
        };
        let pool = GlobalResourcePool::new(config);

        // Request more delta than available
        let request = FatJobRequest {
            scan_ring_bytes: 50_000_000,
            delta_cache_bytes: 50_000_000, // Will fail
            needs_spill_slot: false,
        };

        let permit = pool.try_acquire_fat_job_permit(request);
        assert!(permit.is_none());

        // Scan ring should be fully available (no leak from failed delta)
        assert_eq!(pool.scan_ring_available(), 100_000_000);
        assert_eq!(pool.delta_cache_available(), 10_000_000);
    }

    #[test]
    fn spill_slot_failure_releases_bytes() {
        let config = GlobalResourcePoolConfig {
            scan_ring_bytes: 100_000_000,
            delta_cache_bytes: 100_000_000,
            spill_slots: Some(1), // Only 1 slot
        };
        let pool = GlobalResourcePool::new(config);

        // First request takes the only spill slot
        let request1 = FatJobRequest {
            scan_ring_bytes: 10_000_000,
            delta_cache_bytes: 10_000_000,
            needs_spill_slot: true,
        };
        let p1 = pool.try_acquire_fat_job_permit(request1);
        assert!(p1.is_some());

        // Second request fails on spill slot
        let request2 = FatJobRequest {
            scan_ring_bytes: 10_000_000,
            delta_cache_bytes: 10_000_000,
            needs_spill_slot: true,
        };
        let p2 = pool.try_acquire_fat_job_permit(request2);
        assert!(p2.is_none());

        // Bytes should not be leaked
        // (90MB available = 100MB - 10MB from p1)
        assert_eq!(pool.scan_ring_available(), 90_000_000);
        assert_eq!(pool.delta_cache_available(), 90_000_000);
    }

    /// Regression test: spill-only requests must acquire spill slot
    #[test]
    fn spill_only_request_acquires_slot() {
        let config = GlobalResourcePoolConfig {
            scan_ring_bytes: 100_000_000,
            delta_cache_bytes: 100_000_000,
            spill_slots: Some(1), // Only 1 slot
        };
        let pool = GlobalResourcePool::new(config);

        // Request ONLY spill (no bytes) - this should acquire the slot
        let request = FatJobRequest {
            scan_ring_bytes: 0,
            delta_cache_bytes: 0,
            needs_spill_slot: true,
        };

        let p1 = pool.try_acquire_fat_job_permit(request);
        assert!(p1.is_some(), "spill-only request should succeed");
        assert!(p1.as_ref().unwrap().can_spill());
        assert_eq!(
            pool.spill_slots_available(),
            Some(0),
            "slot should be taken"
        );

        // Second spill-only request should fail
        let p2 = pool.try_acquire_fat_job_permit(request);
        assert!(p2.is_none(), "second spill-only should fail (no slots)");

        // Release and retry
        drop(p1);
        assert_eq!(pool.spill_slots_available(), Some(1));

        let p3 = pool.try_acquire_fat_job_permit(request);
        assert!(p3.is_some(), "should succeed after release");
    }

    #[test]
    fn empty_request_succeeds() {
        let pool = GlobalResourcePool::new(test_config());

        // Truly empty request (no bytes, no spill)
        let request = FatJobRequest {
            scan_ring_bytes: 0,
            delta_cache_bytes: 0,
            needs_spill_slot: false,
        };

        let permit = pool.try_acquire_fat_job_permit(request);
        assert!(permit.is_some());

        let permit = permit.unwrap();
        assert_eq!(permit.scan_ring_bytes(), 0);
        assert_eq!(permit.delta_cache_bytes(), 0);
        assert!(!permit.can_spill()); // Spill not requested
        assert!(!permit.spill_is_limited());
    }

    #[test]
    fn unlimited_spill_mode() {
        let config = GlobalResourcePoolConfig {
            scan_ring_bytes: 100_000_000,
            delta_cache_bytes: 100_000_000,
            spill_slots: None, // Unlimited!
        };
        let pool = GlobalResourcePool::new(config);

        // Request with spill should succeed and show can_spill = true
        let request = FatJobRequest {
            scan_ring_bytes: 10_000_000,
            delta_cache_bytes: 10_000_000,
            needs_spill_slot: true,
        };

        let permit = pool.try_acquire_fat_job_permit(request);
        assert!(permit.is_some());

        let permit = permit.unwrap();
        // Key assertions: can_spill is true, but spill_is_limited is false
        assert!(permit.can_spill(), "unlimited mode should allow spilling");
        assert!(
            !permit.spill_is_limited(),
            "unlimited mode has no counted slot"
        );

        // Multiple permits can all spill
        let p2 = pool.try_acquire_fat_job_permit(request);
        assert!(p2.is_some());
        assert!(p2.unwrap().can_spill());
    }

    #[test]
    fn concurrent_acquisition() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Barrier;
        use std::thread;

        let pool = GlobalResourcePool::new(test_config());
        let success_count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(10));

        // Spawn 10 threads each trying to acquire 20MB (only 5 can succeed at once)
        let handles: Vec<_> = (0..10)
            .map(|_| {
                let pool = Arc::clone(&pool);
                let success_count = Arc::clone(&success_count);
                let barrier = Arc::clone(&barrier);

                thread::spawn(move || {
                    // Synchronize all threads to maximize contention
                    barrier.wait();

                    let request = FatJobRequest {
                        scan_ring_bytes: 20_000_000,
                        delta_cache_bytes: 0,
                        needs_spill_slot: false,
                    };

                    if let Some(permit) = pool.try_acquire_fat_job_permit(request) {
                        success_count.fetch_add(1, Ordering::Relaxed);
                        // Hold permit briefly to create contention
                        thread::sleep(std::time::Duration::from_millis(10));
                        drop(permit);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Key invariant: pool should be fully restored
        assert_eq!(pool.scan_ring_available(), 100_000_000);
    }

    #[test]
    fn permit_size_is_reasonable() {
        let size = std::mem::size_of::<FatJobPermit>();
        assert!(
            size <= 80, // Slightly larger due to SpillGrant enum
            "FatJobPermit size {} exceeds 80 bytes",
            size
        );
        println!("FatJobPermit size: {} bytes", size);
    }

    #[test]
    fn git_repo_helper() {
        let request = FatJobRequest::git_repo(50, 100, true);
        assert_eq!(request.scan_ring_bytes, 50 * 1024 * 1024);
        assert_eq!(request.delta_cache_bytes, 100 * 1024 * 1024);
        assert!(request.needs_spill_slot);
    }

    #[test]
    fn archive_helper() {
        let request = FatJobRequest::archive(10 * 1024 * 1024, false);
        assert_eq!(request.scan_ring_bytes, 10 * 1024 * 1024);
        assert_eq!(request.delta_cache_bytes, 0);
        assert!(!request.needs_spill_slot);
    }

    #[test]
    #[should_panic(expected = "scan_ring_bytes must be > 0")]
    fn config_validation_rejects_zero_scan_ring() {
        let config = GlobalResourcePoolConfig {
            scan_ring_bytes: 0,
            delta_cache_bytes: 100,
            spill_slots: None,
        };
        config.validate();
    }

    #[test]
    #[should_panic(expected = "delta_cache_bytes must be > 0")]
    fn config_validation_rejects_zero_delta_cache() {
        let config = GlobalResourcePoolConfig {
            scan_ring_bytes: 100,
            delta_cache_bytes: 0,
            spill_slots: None,
        };
        config.validate();
    }

    #[test]
    #[should_panic(expected = "spill_slots must be > 0")]
    fn config_validation_rejects_zero_spill_slots() {
        let config = GlobalResourcePoolConfig {
            scan_ring_bytes: 100,
            delta_cache_bytes: 100,
            spill_slots: Some(0),
        };
        config.validate();
    }

    #[test]
    #[should_panic(expected = "scan_ring_mb overflow")]
    fn git_repo_helper_rejects_overflow() {
        // This would overflow: u64::MAX / (1024*1024) ≈ 17.5 million
        let _ = FatJobRequest::git_repo(u64::MAX, 0, false);
    }
}
