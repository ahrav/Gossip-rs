//! CPU affinity for measurement reproducibility.
//!
//! # Purpose
//!
//! Pinning threads to specific CPU cores eliminates variance from:
//! - Core migration overhead (TLB flush, cache invalidation)
//! - NUMA cross-socket latency
//! - Heterogeneous core performance (big.LITTLE, P-cores vs E-cores)
//!
//! This is **measurement hygiene**, not optimization.
//!
//! # Platform Support
//!
//! - **Linux**: Full support via `pthread_setaffinity_np`
//! - **macOS**: Returns `Unsupported` error (macOS doesn't expose per-thread affinity)
//! - **Other**: Returns `Unsupported` error
//!
//! # Container/Cgroup Awareness
//!
//! In containerized environments (Docker, Kubernetes, cgroups), the process may
//! only be allowed to run on a subset of host CPUs. Use `allowed_cpus()` to
//! discover which cores are actually available, not `num_cpus()`.
//!
//! Example: In a container pinned to CPUs 4-7, `pin_current_thread_to_core(0)`
//! will fail even though CPU 0 exists on the host.
//!
//! # Usage
//!
//! ```rust,ignore
//! // Pin to first allowed core for benchmarking
//! if let Some(core) = first_allowed_cpu() {
//!     pin_current_thread_to_core(core)?;
//! }
//!
//! // Or pin to specific isolated core (isolcpus=2 in kernel cmdline)
//! pin_current_thread_to_core(2)?;
//! ```

use std::io;

/// Maximum number of CPUs supported by the affinity API.
///
/// This is `CPU_SETSIZE` on Linux (typically 1024). Core indices must be
/// less than this value to avoid undefined behavior.
#[cfg(target_os = "linux")]
pub const CPU_SET_CAPACITY: usize = {
    // libc::CPU_SETSIZE is not a const fn, so we compute it from the struct size
    // cpu_set_t is a bitmask where each bit represents one CPU
    std::mem::size_of::<libc::cpu_set_t>() * 8
};

#[cfg(not(target_os = "linux"))]
pub const CPU_SET_CAPACITY: usize = 1024; // Reasonable default

/// Validates that a core index is within bounds.
#[inline]
fn validate_core(core: usize) -> io::Result<()> {
    if core >= CPU_SET_CAPACITY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "core index {} exceeds CPU_SET_CAPACITY ({})",
                core, CPU_SET_CAPACITY
            ),
        ));
    }
    Ok(())
}

/// Pins the current thread to a specific CPU core.
///
/// # Arguments
///
/// * `core` - Zero-indexed core number. Must be < `CPU_SET_CAPACITY`.
///
/// # Errors
///
/// Returns an error if:
/// - `core >= CPU_SET_CAPACITY` (would cause undefined behavior)
/// - The core is not in the process's allowed CPU set (cgroups/cpuset)
/// - Permission is denied
/// - The platform is not supported by this library (macOS, Windows)
///
/// # Platform Notes
///
/// - **Linux**: Uses `pthread_setaffinity_np`
/// - **macOS/Other**: Returns `ErrorKind::Unsupported` (not silently ignored!)
#[cfg(target_os = "linux")]
pub fn pin_current_thread_to_core(core: usize) -> io::Result<()> {
    // CRITICAL: Bounds check prevents undefined behavior in CPU_SET macro
    validate_core(core)?;

    // Debug assertion: warn if pinning to a core that's not in allowed set
    #[cfg(debug_assertions)]
    {
        if let Ok(allowed) = allowed_cpus() {
            debug_assert!(
                allowed.is_set(core),
                "Attempting to pin to core {} which is not in allowed set. \
                 This will fail. Use allowed_cpus() to discover valid cores.",
                core
            );
        }
    }

    // SAFETY:
    // - cpu_set_t is valid when zeroed
    // - We validated core < CPU_SET_CAPACITY, so CPU_SET is in bounds
    // - pthread_setaffinity_np returns error codes directly (not via errno)
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core, &mut set);

        let rc = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            std::mem::size_of::<libc::cpu_set_t>(),
            &set as *const _,
        );

        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current_thread_to_core(_core: usize) -> io::Result<()> {
    // Don't silently succeed - that would mislead benchmark results
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "CPU affinity is not supported on this platform",
    ))
}

/// Returns the set of CPUs this process is allowed to run on.
///
/// This respects cgroups, cpusets, and taskset constraints. In containers,
/// this may be a subset of the host's CPUs.
///
/// # Example
///
/// ```rust,ignore
/// let allowed = allowed_cpus()?;
/// for core in 0..CPU_SET_CAPACITY {
///     if allowed.is_set(core) {
///         println!("Can run on core {}", core);
///     }
/// }
/// ```
#[cfg(target_os = "linux")]
pub fn allowed_cpus() -> io::Result<CpuSet> {
    let mut set = CpuSet::new();

    // SAFETY: sched_getaffinity with pid=0 gets the calling thread's affinity
    unsafe {
        let rc = libc::sched_getaffinity(
            0, // 0 = calling thread
            std::mem::size_of::<libc::cpu_set_t>(),
            &mut set.inner as *mut _,
        );

        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(set)
}

#[cfg(not(target_os = "linux"))]
pub fn allowed_cpus() -> io::Result<CpuSet> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "allowed_cpus() is not supported on this platform",
    ))
}

/// Returns the first CPU in the allowed set, if any.
///
/// Useful for benchmarks that need "any valid core" without hardcoding.
#[cfg(target_os = "linux")]
pub fn first_allowed_cpu() -> Option<usize> {
    let allowed = allowed_cpus().ok()?;
    (0..CPU_SET_CAPACITY).find(|&core| allowed.is_set(core))
}

#[cfg(not(target_os = "linux"))]
pub fn first_allowed_cpu() -> Option<usize> {
    None
}

/// Returns the number of available CPUs for parallelism.
///
/// Uses `std::thread::available_parallelism()` which respects:
/// - Cgroup CPU limits (containers)
/// - Processor affinity
/// - Platform-specific constraints
///
/// This is generally more accurate than `sysconf(_SC_NPROCESSORS_ONLN)`
/// which returns the host's total online CPUs regardless of constraints.
///
/// # Fallback
///
/// Returns 1 if parallelism cannot be determined (e.g., exotic platform
/// or permission denied). Code should handle the single-CPU case gracefully.
pub fn num_cpus() -> usize {
    match std::thread::available_parallelism() {
        Ok(n) => n.get(),
        Err(e) => {
            eprintln!(
                "WARN: Could not determine CPU count ({}), defaulting to 1",
                e
            );
            1
        }
    }
}

/// Pins the current thread to a specific core, logging failures.
///
/// This is a convenience wrapper that logs failures to stderr but doesn't
/// propagate them. Use when pinning is "nice to have" but not required.
///
/// Returns `Some(core)` if pinning succeeded, `None` otherwise.
pub fn try_pin_to_core(core: usize) -> Option<usize> {
    match pin_current_thread_to_core(core) {
        Ok(()) => Some(core),
        Err(e) => {
            eprintln!("WARN: Failed to pin thread to core {}: {}", core, e);
            None
        }
    }
}

/// Pins to the first allowed CPU, logging failures.
///
/// Useful for benchmarks in containerized environments where
/// the allowed CPU set is not known in advance.
pub fn try_pin_to_first_allowed() -> Option<usize> {
    let core = first_allowed_cpu()?;
    try_pin_to_core(core)
}

// ============================================================================
// Defaults
// ============================================================================

/// Default for `pin_threads`: enabled on Linux, no-op elsewhere.
pub const fn default_pin_threads() -> bool {
    cfg!(target_os = "linux")
}

// ============================================================================
// CoreAssigner
// ============================================================================

/// Thread-safe round-robin core assigner.
///
/// Distributes threads across available CPU cores using atomic round-robin
/// assignment. Container/cgroup-aware: only assigns cores the process is
/// actually allowed to use.
///
/// # Usage
///
/// ```rust,ignore
/// let assigner = CoreAssigner::new().expect("not on Linux or no allowed CPUs");
/// // In each thread's startup:
/// assigner.pin_current_thread();
/// ```
pub struct CoreAssigner {
    /// Sorted list of allowed core indices (cached at construction).
    cores: Vec<usize>,
    /// Round-robin index (wraps via modulo).
    next: std::sync::atomic::AtomicUsize,
}

impl CoreAssigner {
    /// Create a new assigner using all allowed CPUs.
    ///
    /// Returns `None` on non-Linux platforms or if no allowed CPUs can be
    /// determined.
    pub fn new() -> Option<Self> {
        Self::with_offset(0)
    }

    /// Create a new assigner starting round-robin from `offset`.
    ///
    /// Useful for offsetting I/O threads past CPU worker cores:
    /// ```rust,ignore
    /// let io_assigner = CoreAssigner::with_offset(cpu_worker_count);
    /// ```
    pub fn with_offset(offset: usize) -> Option<Self> {
        let allowed = allowed_cpus().ok()?;
        let cores: Vec<usize> = allowed.iter().collect();
        if cores.is_empty() {
            return None;
        }
        Some(Self {
            cores,
            next: std::sync::atomic::AtomicUsize::new(offset),
        })
    }

    /// Return the next core in round-robin order.
    #[inline]
    pub fn next_core(&self) -> usize {
        let idx = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.cores[idx % self.cores.len()]
    }

    /// Pin the current thread to the next core in round-robin order.
    ///
    /// Returns `Some(core)` on success, `None` on failure (logged to stderr).
    pub fn pin_current_thread(&self) -> Option<usize> {
        try_pin_to_core(self.next_core())
    }

    /// Number of allowed cores.
    #[inline]
    pub fn available(&self) -> usize {
        self.cores.len()
    }
}

// ============================================================================
// CpuSet
// ============================================================================

/// CPU affinity mask.
///
/// On Linux, wraps `cpu_set_t`. On other platforms, this is a zero-sized
/// stub; `set()` and `clear()` are no-ops.
#[derive(Clone, Debug)]
pub struct CpuSet {
    #[cfg(target_os = "linux")]
    inner: libc::cpu_set_t,

    // Non-Linux: zero-sized stub (no dead allocations)
    #[cfg(not(target_os = "linux"))]
    _private: (),
}

impl CpuSet {
    /// Creates an empty CPU set.
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: zeroed cpu_set_t is valid, then we explicitly clear it
            let mut inner: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            // SAFETY: `inner` was zero-initialized above; CPU_ZERO simply
            // clears all bits in a valid cpu_set_t.
            unsafe { libc::CPU_ZERO(&mut inner) };
            Self { inner }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self { _private: () }
        }
    }

    /// Adds a core to the set.
    ///
    /// # Errors
    ///
    /// Returns error if `core >= CPU_SET_CAPACITY`.
    #[cfg(target_os = "linux")]
    pub fn set(&mut self, core: usize) -> io::Result<()> {
        validate_core(core)?;
        // SAFETY: We validated core is in bounds
        unsafe { libc::CPU_SET(core, &mut self.inner) };
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set(&mut self, core: usize) -> io::Result<()> {
        validate_core(core)?;
        // No-op on non-Linux, but we still validate
        Ok(())
    }

    /// Removes a core from the set.
    ///
    /// # Errors
    ///
    /// Returns error if `core >= CPU_SET_CAPACITY`.
    #[cfg(target_os = "linux")]
    pub fn clear(&mut self, core: usize) -> io::Result<()> {
        validate_core(core)?;
        // SAFETY: We validated core is in bounds
        unsafe { libc::CPU_CLR(core, &mut self.inner) };
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn clear(&mut self, core: usize) -> io::Result<()> {
        validate_core(core)?;
        Ok(())
    }

    /// Checks if a core is in the set.
    ///
    /// Returns `false` if `core >= CPU_SET_CAPACITY` (instead of UB).
    #[cfg(target_os = "linux")]
    pub fn is_set(&self, core: usize) -> bool {
        if core >= CPU_SET_CAPACITY {
            return false;
        }
        // SAFETY: We validated core is in bounds
        unsafe { libc::CPU_ISSET(core, &self.inner) }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn is_set(&self, _core: usize) -> bool {
        false // Non-Linux stub has no cores set
    }

    /// Returns the number of CPUs in the set.
    #[cfg(target_os = "linux")]
    pub fn count(&self) -> usize {
        // SAFETY: CPU_COUNT is safe on valid cpu_set_t
        unsafe { libc::CPU_COUNT(&self.inner) as usize }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn count(&self) -> usize {
        0
    }

    /// Applies this CPU set to the current thread.
    ///
    /// # Errors
    ///
    /// Returns error on failure or if platform doesn't support affinity.
    #[cfg(target_os = "linux")]
    pub fn apply(&self) -> io::Result<()> {
        // SAFETY: pthread_setaffinity_np is safe with valid cpu_set_t
        unsafe {
            let rc = libc::pthread_setaffinity_np(
                libc::pthread_self(),
                std::mem::size_of::<libc::cpu_set_t>(),
                &self.inner as *const _,
            );
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "CPU affinity is not supported on this platform",
        ))
    }

    /// Returns an iterator over set core indices.
    ///
    /// # Complexity
    ///
    /// O(CPU_SET_CAPACITY) - always scans the full bitmask. For sparse sets
    /// with few cores, this is acceptable. For tight loops needing only the
    /// count, use `count()` instead.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..CPU_SET_CAPACITY).filter(move |&core| self.is_set(core))
    }
}

impl Default for CpuSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_cpus_returns_positive() {
        let n = num_cpus();
        assert!(n >= 1, "Expected at least 1 CPU, got {}", n);
    }

    #[test]
    fn cpu_set_capacity_is_reasonable() {
        // Should be at least 64 (minimum sensible value)
        // and at most 8192 (nobody has that many CPUs in one system... yet)
        const { assert!(CPU_SET_CAPACITY >= 64) };
        const { assert!(CPU_SET_CAPACITY <= 8192) };
    }

    #[test]
    fn validate_core_rejects_out_of_bounds() {
        assert!(validate_core(0).is_ok());
        assert!(validate_core(CPU_SET_CAPACITY - 1).is_ok());
        assert!(validate_core(CPU_SET_CAPACITY).is_err());
        assert!(validate_core(CPU_SET_CAPACITY + 1).is_err());
        assert!(validate_core(usize::MAX).is_err());
    }

    #[test]
    fn cpu_set_operations_with_bounds_check() {
        let mut set = CpuSet::new();

        // Valid operations
        assert!(set.set(0).is_ok());
        assert!(set.set(63).is_ok());

        // Out of bounds
        assert!(set.set(CPU_SET_CAPACITY).is_err());
        assert!(set.set(usize::MAX).is_err());
        assert!(set.clear(CPU_SET_CAPACITY).is_err());

        // is_set returns false for out of bounds (not UB)
        assert!(!set.is_set(CPU_SET_CAPACITY));
        assert!(!set.is_set(usize::MAX));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn cpu_set_basic_linux() {
        let mut set = CpuSet::new();

        assert!(!set.is_set(0));
        assert!(!set.is_set(1));

        set.set(0).unwrap();
        set.set(2).unwrap();

        assert!(set.is_set(0));
        assert!(!set.is_set(1));
        assert!(set.is_set(2));
        assert_eq!(set.count(), 2);

        set.clear(0).unwrap();
        assert!(!set.is_set(0));
        assert!(set.is_set(2));
        assert_eq!(set.count(), 1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn allowed_cpus_returns_nonempty() {
        let allowed = allowed_cpus().expect("allowed_cpus should succeed");
        assert!(
            allowed.count() > 0,
            "Process should be allowed on at least 1 CPU"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn first_allowed_cpu_exists() {
        let first = first_allowed_cpu();
        assert!(first.is_some(), "Should have at least one allowed CPU");

        // The returned core should actually be in the allowed set
        let allowed = allowed_cpus().unwrap();
        assert!(allowed.is_set(first.unwrap()));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn pin_to_allowed_cpu_succeeds() {
        if let Some(core) = first_allowed_cpu() {
            let result = pin_current_thread_to_core(core);
            assert!(
                result.is_ok(),
                "Pinning to allowed core {} should succeed: {:?}",
                core,
                result
            );
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn pin_to_out_of_bounds_fails_safely() {
        // This should return an error, not cause UB
        let result = pin_current_thread_to_core(CPU_SET_CAPACITY);
        assert!(result.is_err());

        let result = pin_current_thread_to_core(usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn pin_returns_unsupported_on_non_linux() {
        let result = pin_current_thread_to_core(0);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn allowed_cpus_unsupported_on_non_linux() {
        let result = allowed_cpus();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn cpu_set_iter() {
        let mut set = CpuSet::new();
        let _ = set.set(1);
        let _ = set.set(3);
        let _ = set.set(5);

        #[cfg(target_os = "linux")]
        {
            let cores: Vec<usize> = set.iter().collect();
            assert_eq!(cores, vec![1, 3, 5]);
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Non-Linux always returns empty
            let cores: Vec<usize> = set.iter().collect();
            assert!(cores.is_empty());
        }
    }

    #[test]
    fn try_pin_logs_on_failure() {
        // On non-Linux, this will print a warning and return None
        // On Linux with invalid core, same behavior
        let result = try_pin_to_core(CPU_SET_CAPACITY);
        assert!(result.is_none());
    }

    #[test]
    fn default_pin_threads_matches_platform() {
        let expected = cfg!(target_os = "linux");
        assert_eq!(default_pin_threads(), expected);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn core_assigner_round_robin() {
        let assigner = CoreAssigner::new().expect("should succeed on Linux");
        assert!(assigner.available() > 0);

        // Collect cores across multiple calls - should cycle
        let n = assigner.available() * 2;
        let mut assigned: Vec<usize> = Vec::with_capacity(n);
        for _ in 0..n {
            assigned.push(assigner.next_core());
        }

        // Second half should repeat first half (round-robin wrap)
        let half = assigner.available();
        assert_eq!(&assigned[..half], &assigned[half..]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn core_assigner_with_offset() {
        let a0 = CoreAssigner::with_offset(0).expect("should succeed on Linux");
        let a1 = CoreAssigner::with_offset(1).expect("should succeed on Linux");

        let first_from_0 = a0.next_core();
        let first_from_1 = a1.next_core();

        // With offset=1, the first core should be the second in the list
        if a0.available() > 1 {
            assert_ne!(first_from_0, first_from_1);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn core_assigner_pin_succeeds() {
        let assigner = CoreAssigner::new().expect("should succeed on Linux");
        let pinned = assigner.pin_current_thread();
        assert!(pinned.is_some(), "pin should succeed on allowed core");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn core_assigner_returns_none_on_non_linux() {
        assert!(CoreAssigner::new().is_none());
    }
}
