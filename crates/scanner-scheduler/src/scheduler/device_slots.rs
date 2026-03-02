//! Device Slots for mmap-Based I/O Fairness
//!
//! # Purpose
//!
//! Provides fairness control for mmap-based sources (Git repos, large files)
//! that share the same physical storage device. Without limits, multiple
//! concurrent mmap operations on the same disk can cause page cache thrashing
//! and catastrophic throughput collapse.
//!
//! # Problem Solved
//!
//! When using mmap for pack file decoding, disk I/O happens as page faults
//! and bypasses explicit "in-flight read" accounting. Device slots provide
//! a coarse-grained admission control that limits concurrent mmap-heavy
//! operations per physical device.
//!
//! # Architecture
//!
//! ```text
//! DeviceSlots (per filesystem/mount)
//!     └── CountBudget (N slots)
//!         └── DeviceSlotPermit (RAII)
//! ```
//!
//! # Contract
//!
//! This is **advisory fairness**, not a hard I/O cap:
//!
//! - The scheduler controls: concurrent fat jobs per filesystem/mount
//! - The scheduler does NOT control: actual disk I/O timing (page faults are implicit)
//! - Device slot limits provide fairness, not hard I/O caps
//!
//! # Limitations
//!
//! ## `st_dev` is Filesystem Identity, Not Physical Device
//!
//! On Unix, we use `st_dev` from stat(2). This identifies the filesystem/mount,
//! not the physical disk. Implications:
//!
//! - Different partitions on the same physical disk get different `st_dev` values
//! - Jobs on separate partitions of the same disk aren't coalesced
//! - Bind mounts share `st_dev` (correct behavior)
//!
//! For true physical device identity, OS-specific mapping is needed (Linux sysfs,
//! macOS IOKit). This is a future enhancement.
//!
//! ## Budget Map Growth
//!
//! The per-device budget map grows monotonically. This is acceptable for:
//! - CI/CD scanning with stable device sets
//! - Short-lived processes
//!
//! For long-running daemons with ephemeral mounts, consider periodic pruning
//! (not currently implemented).
//!
//! # When to Use
//!
//! Use device slots when:
//! - Source uses mmap for data access (Git pack files, large archives)
//! - Multiple concurrent jobs may target the same filesystem
//! - Page cache pressure is a concern
//!
//! Do NOT use when:
//! - Source uses explicit reads through the I/O engine
//! - Jobs are known to be on different filesystems
//! - Memory is sufficient to cache all working sets

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::scheduler::count_budget::{CountBudget, CountPermit};

// ============================================================================
// DeviceId
// ============================================================================

/// Identifier for a storage device (filesystem/mount on Unix).
///
/// # Platform Support
///
/// - **Unix (Linux, macOS)**: Uses `st_dev` from stat(2) - identifies filesystem/mount
/// - **Non-Unix (Windows, etc.)**: Falls back to `DeviceId::UNKNOWN` (single global pool)
///
/// # Windows Note
///
/// Windows support is not currently implemented. All paths on Windows will use
/// the UNKNOWN device, resulting in global serialization of all mmap-heavy jobs.
/// This is safe but suboptimal. A future enhancement could use
/// `GetVolumeInformationByHandleW` to get volume serial numbers.
///
/// # Fallback
///
/// When device detection fails (path doesn't exist, permission denied, etc.),
/// returns `DeviceId::UNKNOWN` which maps all such paths to a single slot pool.
/// Use `try_from_path()` if you need to distinguish detection failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceId(u64);

impl DeviceId {
    /// Unknown device (fallback when detection fails).
    ///
    /// All paths with unknown devices share a single slot pool.
    ///
    /// Uses `u64::MAX` as sentinel to avoid collision with real `st_dev` values.
    /// On Unix, `st_dev` is typically 32-bit or 64-bit but practically never
    /// reaches `u64::MAX`.
    pub const UNKNOWN: DeviceId = DeviceId(u64::MAX);

    /// Detect the device ID for a path.
    ///
    /// # Platform Behavior
    ///
    /// - Unix: Returns `st_dev` from the file's metadata
    /// - Non-Unix: Returns `DeviceId::UNKNOWN`
    ///
    /// # Errors
    ///
    /// Returns `DeviceId::UNKNOWN` if:
    /// - Path doesn't exist
    /// - Permission denied
    /// - Other I/O error
    ///
    /// Use `try_from_path()` if you need to handle errors explicitly.
    #[cfg(unix)]
    pub fn from_path(path: &Path) -> Self {
        Self::try_from_path(path).unwrap_or(DeviceId::UNKNOWN)
    }

    #[cfg(not(unix))]
    pub fn from_path(_path: &Path) -> Self {
        // Non-Unix platforms: fall back to single pool
        // See module docs for Windows note
        DeviceId::UNKNOWN
    }

    /// Try to detect the device ID for a path, returning errors explicitly.
    ///
    /// # Platform Behavior
    ///
    /// - Unix: Returns `st_dev` from the file's metadata
    /// - Non-Unix: Always returns `Ok(DeviceId::UNKNOWN)`
    ///
    /// # Performance Note
    ///
    /// Performs a `stat(2)` syscall on Unix. Cache the result at job creation
    /// time rather than calling repeatedly.
    #[cfg(unix)]
    pub fn try_from_path(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(DeviceId(meta.dev()))
    }

    #[cfg(not(unix))]
    pub fn try_from_path(_path: &Path) -> std::io::Result<Self> {
        Ok(DeviceId::UNKNOWN)
    }

    /// Create a device ID from a raw value (for testing).
    ///
    /// # Note
    ///
    /// Using `u64::MAX` will create a device ID equal to `UNKNOWN`.
    pub fn from_raw(raw: u64) -> Self {
        DeviceId(raw)
    }

    /// Get the raw device ID value.
    #[inline]
    pub fn raw(&self) -> u64 {
        self.0
    }

    /// Check if this is the unknown device.
    #[inline]
    pub fn is_unknown(&self) -> bool {
        *self == Self::UNKNOWN
    }
}

// ============================================================================
// DeviceSlotsConfig
// ============================================================================

/// Configuration for device slot allocation.
///
/// # Validation
///
/// Configuration is validated when passed to `DeviceSlots::new()`. Invalid
/// configurations (zero slots) will panic.
#[derive(Clone, Debug)]
pub struct DeviceSlotsConfig {
    /// Default slots per device when not explicitly configured.
    pub default_slots: usize,

    /// Per-device slot overrides.
    ///
    /// Use when certain devices need different concurrency limits
    /// (e.g., fast NVMe vs slow HDD).
    pub device_overrides: HashMap<DeviceId, usize>,
}

impl Default for DeviceSlotsConfig {
    fn default() -> Self {
        Self {
            default_slots: 4, // Conservative default
            device_overrides: HashMap::new(),
        }
    }
}

impl DeviceSlotsConfig {
    /// Create config with uniform slots for all devices.
    ///
    /// # Panics
    ///
    /// Panics if `slots` is 0.
    pub fn uniform(slots: usize) -> Self {
        assert!(slots > 0, "slots must be > 0");
        Self {
            default_slots: slots,
            device_overrides: HashMap::new(),
        }
    }

    /// Add a per-device override.
    ///
    /// # Panics
    ///
    /// Panics if `slots` is 0.
    pub fn with_device(mut self, device: DeviceId, slots: usize) -> Self {
        assert!(slots > 0, "slots must be > 0");
        self.device_overrides.insert(device, slots);
        self
    }

    /// Validate the configuration.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `default_slots` is 0
    /// - Any device override has 0 slots
    fn validate(&self) {
        assert!(self.default_slots > 0, "default_slots must be > 0");
        for (&device, &slots) in &self.device_overrides {
            assert!(slots > 0, "device {:?} has invalid slot count 0", device);
        }
    }
}

// ============================================================================
// DeviceSlots
// ============================================================================

/// Device slot allocator for mmap-based I/O fairness.
///
/// # Thread Safety
///
/// Safe to share via `Arc<DeviceSlots>`. Internal budgets are created
/// lazily and protected by mutex synchronization.
///
/// # Usage
///
/// ```ignore
/// let slots = DeviceSlots::new(DeviceSlotsConfig::uniform(4));
///
/// // Before starting a mmap-heavy job - cache device ID at discovery time
/// let device = DeviceId::from_path(repo_path);
///
/// // Later, when starting the job
/// let permit = slots.try_acquire(device);
///
/// match permit {
///     Some(p) => {
///         // Proceed with mmap-based scanning
///         scan_with_mmap(repo, p);
///     }
///     None => {
///         // Too many concurrent jobs on this device
///         requeue_for_later();
///     }
/// }
/// ```
#[derive(Debug)]
pub struct DeviceSlots {
    /// Configuration (immutable after construction).
    config: DeviceSlotsConfig,

    /// Per-device budgets (lazily created).
    ///
    /// Uses `std::sync::Mutex` which is sufficient for job-level acquisition
    /// rates (tens/sec). The critical section is small (HashMap lookup/insert).
    budgets: std::sync::Mutex<HashMap<DeviceId, Arc<CountBudget>>>,
}

impl DeviceSlots {
    /// Create a new device slot allocator.
    ///
    /// # Panics
    ///
    /// Panics if configuration is invalid (zero slots).
    pub fn new(config: DeviceSlotsConfig) -> Arc<Self> {
        config.validate();

        Arc::new(Self {
            config,
            budgets: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Create with uniform slots (convenience constructor).
    ///
    /// # Panics
    ///
    /// Panics if `slots` is 0.
    pub fn uniform(slots: usize) -> Arc<Self> {
        Self::new(DeviceSlotsConfig::uniform(slots))
    }

    /// Lock budgets with poison recovery.
    ///
    /// If the mutex was poisoned by a panic in another thread, we recover
    /// the inner map and continue. The alternative (panic) would cascade
    /// failures unnecessarily.
    fn lock_budgets(&self) -> std::sync::MutexGuard<'_, HashMap<DeviceId, Arc<CountBudget>>> {
        match self.budgets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Recover from poison - the map is still usable
                poisoned.into_inner()
            }
        }
    }

    /// Get or create the budget for a device.
    fn get_or_create_budget(&self, device: DeviceId) -> Arc<CountBudget> {
        let mut budgets = self.lock_budgets();

        if let Some(budget) = budgets.get(&device) {
            return Arc::clone(budget);
        }

        // Determine slot count for this device
        let slots = self
            .config
            .device_overrides
            .get(&device)
            .copied()
            .unwrap_or(self.config.default_slots);

        // This assertion should never fire due to config validation,
        // but Tiger Style says verify anyway
        debug_assert!(
            slots > 0,
            "slot count must be positive (config validation failed?)"
        );

        let budget = CountBudget::new(slots);
        budgets.insert(device, Arc::clone(&budget));

        debug_assert!(
            budgets.contains_key(&device),
            "budget must be in map after insert"
        );

        budget
    }

    /// Try to acquire a device slot without blocking.
    ///
    /// # Parameters
    ///
    /// - `device`: The device to acquire a slot for
    ///
    /// # Returns
    ///
    /// `Some(permit)` if a slot is available, `None` if device is at capacity.
    #[must_use = "permit is released on drop; ignoring result wastes the attempt"]
    pub fn try_acquire(self: &Arc<Self>, device: DeviceId) -> Option<DeviceSlotPermit> {
        let budget = self.get_or_create_budget(device);

        budget.try_acquire(1).map(|permit| DeviceSlotPermit {
            _inner: permit,
            device,
        })
    }

    /// Acquire a device slot, blocking until available.
    ///
    /// # Warning
    ///
    /// DO NOT call this from executor worker threads. Use `try_acquire()`
    /// and re-enqueue on failure. Blocking from worker threads can cause
    /// deadlock if all threads block while permits are held by queued tasks.
    ///
    /// Safe to call from:
    /// - Dedicated discovery threads
    /// - External callers before starting executor
    /// - Initialization code
    pub fn acquire(self: &Arc<Self>, device: DeviceId) -> DeviceSlotPermit {
        let budget = self.get_or_create_budget(device);

        DeviceSlotPermit {
            _inner: budget.acquire(1),
            device,
        }
    }

    /// Try to acquire a slot for a path (detects device automatically).
    ///
    /// Convenience method that combines device detection with slot acquisition.
    ///
    /// # Performance Note
    ///
    /// Performs a `stat(2)` syscall to detect the device. For hot paths,
    /// cache the `DeviceId` at job discovery time and use `try_acquire()`
    /// directly.
    pub fn try_acquire_for_path(self: &Arc<Self>, path: &Path) -> Option<DeviceSlotPermit> {
        let device = DeviceId::from_path(path);
        self.try_acquire(device)
    }

    /// Get available slots for a device.
    ///
    /// Returns `None` if the device has no budget yet (never accessed).
    pub fn available(&self, device: DeviceId) -> Option<usize> {
        let budgets = self.lock_budgets();
        budgets.get(&device).map(|b| b.available())
    }

    /// Get total slots for a device.
    pub fn total(&self, device: DeviceId) -> usize {
        self.config
            .device_overrides
            .get(&device)
            .copied()
            .unwrap_or(self.config.default_slots)
    }

    /// Get the number of devices with active budgets.
    pub fn active_device_count(&self) -> usize {
        let budgets = self.lock_budgets();
        budgets.len()
    }
}

// ============================================================================
// DeviceSlotPermit
// ============================================================================

/// RAII permit for a device slot.
///
/// # Lifetime
///
/// Hold this permit for the duration of mmap-heavy operations on the device.
/// When dropped, the slot is released and another job can proceed.
///
/// # Typical Usage
///
/// ```ignore
/// struct GitRepoJob {
///     device_slot: DeviceSlotPermit,
///     fat_job_permit: FatJobPermit,
///     // ... other fields ...
/// }
///
/// // Both permits released when job completes or is cancelled
/// ```
#[derive(Debug)]
#[must_use = "DeviceSlotPermit releases on drop; not holding it defeats fairness"]
pub struct DeviceSlotPermit {
    _inner: CountPermit,
    device: DeviceId,
}

impl DeviceSlotPermit {
    /// Get the device this permit is for.
    #[inline]
    pub fn device(&self) -> DeviceId {
        self.device
    }
}

// ============================================================================
// IoModel - Explicit I/O Contract Documentation
// ============================================================================

/// I/O model for a source type.
///
/// The scheduler uses this to determine which resource limits apply.
/// This is documentation of the contract, not enforcement.
///
/// # Usage with DeviceSlots
///
/// ```ignore
/// let io_model = source.io_model();
/// if io_model.uses_device_slots() {
///     let permit = device_slots.try_acquire(device)?;
///     // ... use mmap-based scanning ...
/// } else {
///     // ... use explicit I/O through buffer pool ...
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoModel {
    /// Explicit reads through scheduler's I/O stage.
    ///
    /// Scheduler controls:
    /// - Buffer pool allocation
    /// - Read token permits
    /// - Bytes in flight
    ///
    /// Use for: Remote backends (S3, HTTP), local files with io_uring
    ExplicitReads,

    /// Memory-mapped I/O with implicit page faults.
    ///
    /// Scheduler controls:
    /// - Device slots (concurrent jobs per device)
    /// - Global memory budgets (FatJobPermit)
    ///
    /// Scheduler does NOT control:
    /// - Actual disk I/O timing (page faults are OS-driven)
    /// - Page cache eviction (kernel decides)
    /// - Read-ahead behavior (madvise is advisory)
    ///
    /// Use for: Git pack files, large local archives
    MmapImplicit,
}

impl IoModel {
    /// Returns true if this model uses device slots.
    #[inline]
    pub fn uses_device_slots(&self) -> bool {
        matches!(self, IoModel::MmapImplicit)
    }

    /// Returns true if this model uses explicit read tokens.
    #[inline]
    pub fn uses_read_tokens(&self) -> bool {
        matches!(self, IoModel::ExplicitReads)
    }
}

// ============================================================================
// Compile-time assertions
// ============================================================================

const _: () = {
    // DeviceId should be small and trivially copyable
    assert!(std::mem::size_of::<DeviceId>() == 8);
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn basic_acquire_release() {
        let slots = DeviceSlots::uniform(2);
        let device = DeviceId::from_raw(1);

        let p1 = slots.try_acquire(device);
        assert!(p1.is_some());
        assert_eq!(slots.available(device), Some(1));

        let p2 = slots.try_acquire(device);
        assert!(p2.is_some());
        assert_eq!(slots.available(device), Some(0));

        // Third should fail
        let p3 = slots.try_acquire(device);
        assert!(p3.is_none());

        // Release one
        drop(p1);
        assert_eq!(slots.available(device), Some(1));

        // Now can acquire
        let p3 = slots.try_acquire(device);
        assert!(p3.is_some());
    }

    #[test]
    fn different_devices_independent() {
        let slots = DeviceSlots::uniform(1);

        let device1 = DeviceId::from_raw(1);
        let device2 = DeviceId::from_raw(2);

        let p1 = slots.try_acquire(device1);
        assert!(p1.is_some());

        // Different device should succeed
        let p2 = slots.try_acquire(device2);
        assert!(p2.is_some());

        // Same device should fail
        let p3 = slots.try_acquire(device1);
        assert!(p3.is_none());
    }

    #[test]
    fn device_overrides() {
        let config = DeviceSlotsConfig::uniform(2).with_device(DeviceId::from_raw(1), 5);

        let slots = DeviceSlots::new(config);

        // Device 1 has 5 slots
        assert_eq!(slots.total(DeviceId::from_raw(1)), 5);

        // Device 2 has default (2 slots)
        assert_eq!(slots.total(DeviceId::from_raw(2)), 2);
    }

    #[test]
    fn unknown_device_works() {
        let slots = DeviceSlots::uniform(2);

        let p1 = slots.try_acquire(DeviceId::UNKNOWN);
        assert!(p1.is_some());

        let p2 = slots.try_acquire(DeviceId::UNKNOWN);
        assert!(p2.is_some());

        let p3 = slots.try_acquire(DeviceId::UNKNOWN);
        assert!(p3.is_none());
    }

    #[test]
    fn unknown_sentinel_is_max() {
        // Verify UNKNOWN uses u64::MAX to avoid collision with real st_dev
        assert_eq!(DeviceId::UNKNOWN.raw(), u64::MAX);
        assert!(DeviceId::UNKNOWN.is_unknown());
        assert!(!DeviceId::from_raw(0).is_unknown());
        assert!(!DeviceId::from_raw(1).is_unknown());
    }

    #[test]
    fn device_id_zero_is_valid() {
        // st_dev of 0 is rare but valid on some systems
        // It should NOT be treated as UNKNOWN
        let device_zero = DeviceId::from_raw(0);
        assert!(!device_zero.is_unknown());
        assert_ne!(device_zero, DeviceId::UNKNOWN);
    }

    #[test]
    fn concurrent_acquisition_with_barrier() {
        let slots = DeviceSlots::uniform(3);
        let device = DeviceId::from_raw(1);
        let barrier = Arc::new(Barrier::new(10));
        let acquired_count = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let slots = Arc::clone(&slots);
                let barrier = Arc::clone(&barrier);
                let acquired_count = Arc::clone(&acquired_count);
                let max_concurrent = Arc::clone(&max_concurrent);

                thread::spawn(move || {
                    // Synchronize all threads to maximize contention
                    barrier.wait();

                    if let Some(_permit) = slots.try_acquire(device) {
                        let current = acquired_count.fetch_add(1, Ordering::SeqCst) + 1;

                        // Track max concurrent
                        let mut max = max_concurrent.load(Ordering::Relaxed);
                        while current > max {
                            match max_concurrent.compare_exchange_weak(
                                max,
                                current,
                                Ordering::SeqCst,
                                Ordering::Relaxed,
                            ) {
                                Ok(_) => break,
                                Err(m) => max = m,
                            }
                        }

                        // Wait for all threads to attempt acquisition
                        barrier.wait();

                        // Release
                        acquired_count.fetch_sub(1, Ordering::SeqCst);
                    } else {
                        // Wait for others
                        barrier.wait();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Max concurrent should be exactly 3 (our slot limit)
        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            3,
            "max concurrent should equal slot limit"
        );

        // All should be released
        assert_eq!(slots.available(device), Some(3));
    }

    #[test]
    fn blocking_acquire() {
        let slots = DeviceSlots::uniform(1);
        let device = DeviceId::from_raw(1);

        // Take the only slot
        let p1 = slots.acquire(device);
        assert!(slots.try_acquire(device).is_none());

        // Spawn thread that will wait
        let slots_clone = Arc::clone(&slots);
        let handle = thread::spawn(move || {
            let _p2 = slots_clone.acquire(device);
            // Got it!
        });

        // Give thread time to block
        thread::sleep(std::time::Duration::from_millis(50));

        // Release first permit
        drop(p1);

        // Thread should complete
        handle.join().unwrap();

        // Slot should be released
        assert_eq!(slots.available(device), Some(1));
    }

    #[test]
    fn permit_reports_device() {
        let slots = DeviceSlots::uniform(2);
        let device = DeviceId::from_raw(42);

        let permit = slots.try_acquire(device).unwrap();
        assert_eq!(permit.device(), device);
    }

    #[test]
    fn active_device_count() {
        let slots = DeviceSlots::uniform(2);

        assert_eq!(slots.active_device_count(), 0);

        let _p1 = slots.try_acquire(DeviceId::from_raw(1));
        assert_eq!(slots.active_device_count(), 1);

        let _p2 = slots.try_acquire(DeviceId::from_raw(2));
        assert_eq!(slots.active_device_count(), 2);

        // Same device doesn't increase count
        let _p3 = slots.try_acquire(DeviceId::from_raw(1));
        assert_eq!(slots.active_device_count(), 2);
    }

    #[test]
    fn io_model_queries() {
        assert!(IoModel::MmapImplicit.uses_device_slots());
        assert!(!IoModel::MmapImplicit.uses_read_tokens());

        assert!(!IoModel::ExplicitReads.uses_device_slots());
        assert!(IoModel::ExplicitReads.uses_read_tokens());
    }

    #[cfg(unix)]
    #[test]
    fn device_id_from_real_path() {
        // Use temp_dir which should exist on any Unix system
        let temp = std::env::temp_dir();
        let device = DeviceId::from_path(&temp);

        // Should get a real device ID, not UNKNOWN
        // (temp_dir should always be accessible)
        assert!(
            !device.is_unknown(),
            "temp_dir should have a valid device ID"
        );
    }

    #[test]
    fn device_id_from_nonexistent_path() {
        let device = DeviceId::from_path(Path::new("/nonexistent/path/12345"));
        assert!(device.is_unknown());
    }

    #[cfg(unix)]
    #[test]
    fn try_from_path_returns_error() {
        let result = DeviceId::try_from_path(Path::new("/nonexistent/path/12345"));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn try_from_path_success() {
        let temp = std::env::temp_dir();
        let result = DeviceId::try_from_path(&temp);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_unknown());
    }

    #[test]
    fn permit_size_is_reasonable() {
        let size = std::mem::size_of::<DeviceSlotPermit>();
        assert!(
            size <= 48,
            "DeviceSlotPermit size {} exceeds 48 bytes",
            size
        );
        println!("DeviceSlotPermit size: {} bytes", size);
    }

    #[test]
    #[should_panic(expected = "slots must be > 0")]
    fn config_uniform_rejects_zero() {
        let _ = DeviceSlotsConfig::uniform(0);
    }

    #[test]
    #[should_panic(expected = "slots must be > 0")]
    fn config_with_device_rejects_zero() {
        let _ = DeviceSlotsConfig::uniform(2).with_device(DeviceId::from_raw(1), 0);
    }

    #[test]
    #[should_panic(expected = "default_slots must be > 0")]
    fn new_validates_config() {
        // Bypass uniform() validation by constructing directly
        let config = DeviceSlotsConfig {
            default_slots: 0,
            device_overrides: HashMap::new(),
        };
        let _ = DeviceSlots::new(config);
    }

    #[test]
    #[should_panic(expected = "device")]
    fn new_validates_overrides() {
        let mut overrides = HashMap::new();
        overrides.insert(DeviceId::from_raw(1), 0);

        let config = DeviceSlotsConfig {
            default_slots: 4,
            device_overrides: overrides,
        };
        let _ = DeviceSlots::new(config);
    }
}
