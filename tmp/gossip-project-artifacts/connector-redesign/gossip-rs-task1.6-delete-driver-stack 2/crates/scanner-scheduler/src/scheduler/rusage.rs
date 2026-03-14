//! Process resource usage measurement.
//!
//! # Purpose
//!
//! Captures process-level resource metrics for benchmark reproducibility:
//! - User CPU time: time spent in user mode
//! - System CPU time: time spent in kernel mode  
//! - Max RSS: peak memory usage (high-water mark)
//!
//! # Important Semantics
//!
//! **CPU time vs wall time**: In parallel workloads, `user_time + sys_time`
//! can exceed wall time by approximately the number of active cores. This is
//! correct - it measures total CPU consumed, not latency.
//!
//! **RSS is a high-water mark**: `max_rss_bytes` only ever stays flat or
//! increases within a process lifetime. Running multiple benchmark iterations
//! in one process will show the peak across all iterations.
//!
//! **Syscall cost**: `getrusage()` is a syscall (~200ns). Use at coarse
//! boundaries (per-run, per-phase), not in hot paths (per-chunk, per-file).
//!
//! # Platform Support
//!
//! | Platform | `ru_maxrss` units | Supported |
//! |----------|-------------------|-----------|
//! | Linux | KiB | âœ“ |
//! | macOS | bytes | âœ“ |
//! | FreeBSD/NetBSD/OpenBSD/DragonFly | KiB | âœ“ |
//! | Android | KiB | âœ“ |
//! | Other Unix | unknown | Returns 0 |
//! | Non-Unix | N/A | Returns defaults |
//!
//! # Usage
//!
//! ```rust,ignore
//! let before = rusage_self();
//! // ... do work ...
//! let after = rusage_self();
//!
//! let delta = after.since(&before);
//! println!("CPU: {:?}, RSS: {} bytes", delta.total_cpu_time(), delta.ending_max_rss_bytes);
//! ```

use std::time::Duration;

/// Process resource usage snapshot.
///
/// All fields are best-effort: if `getrusage` fails, defaults to zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcUsage {
    /// Time spent executing in user mode.
    pub user_time: Duration,
    /// Time spent executing in kernel mode.
    pub sys_time: Duration,
    /// Maximum resident set size in bytes (high-water mark).
    ///
    /// This is the peak RSS since process start, not current RSS.
    /// It can only stay flat or increase over the process lifetime.
    pub max_rss_bytes: u64,
}

impl ProcUsage {
    /// Returns total CPU time (user + system).
    ///
    /// Note: In parallel workloads, this can exceed wall time by ~#cores.
    #[inline]
    pub fn total_cpu_time(&self) -> Duration {
        self.user_time.saturating_add(self.sys_time)
    }

    /// Computes difference from an earlier snapshot.
    ///
    /// For user/sys time, returns the delta. For RSS, returns the
    /// ending high-water mark (NOT a delta - RSS deltas are meaningless
    /// since it's a high-water mark).
    #[inline]
    pub fn since(&self, earlier: &ProcUsage) -> ProcUsageDelta {
        ProcUsageDelta {
            user_time: self.user_time.saturating_sub(earlier.user_time),
            sys_time: self.sys_time.saturating_sub(earlier.sys_time),
            ending_max_rss_bytes: self.max_rss_bytes,
        }
    }
}

/// Difference in resource usage between two snapshots.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcUsageDelta {
    /// User CPU time consumed during interval.
    pub user_time: Duration,
    /// System CPU time consumed during interval.
    pub sys_time: Duration,
    /// Max RSS at end of interval.
    ///
    /// **This is NOT a delta** - it's the absolute high-water mark at
    /// measurement time. Named explicitly to avoid confusion.
    pub ending_max_rss_bytes: u64,
}

impl ProcUsageDelta {
    /// Total CPU time consumed.
    #[inline]
    pub fn total_cpu_time(&self) -> Duration {
        self.user_time.saturating_add(self.sys_time)
    }
}

// ============================================================================
// Internal implementation (DRY)
// ============================================================================

/// Converts a `libc::timeval` to `Duration`.
///
/// Handles invalid values defensively:
/// - Negative seconds â†’ 0
/// - Negative or out-of-range microseconds â†’ clamped to [0, 999_999]
#[cfg(unix)]
#[inline]
fn timeval_to_duration(tv: libc::timeval) -> Duration {
    let secs = if tv.tv_sec < 0 { 0 } else { tv.tv_sec as u64 };
    // POSIX specifies tv_usec in [0, 999_999]. Clamp defensively.
    let usec = tv.tv_usec.clamp(0, 999_999) as u64;
    Duration::from_secs(secs) + Duration::from_micros(usec)
}

/// Converts `ru_maxrss` to bytes based on platform.
///
/// Returns 0 for unsupported platforms rather than returning a value
/// with unknown units that would be silently wrong.
#[cfg(unix)]
#[inline]
fn maxrss_to_bytes(ru_maxrss: libc::c_long) -> u64 {
    let rss_u64 = if ru_maxrss <= 0 { 0 } else { ru_maxrss as u64 };

    // Linux, Android, and BSDs: ru_maxrss is in kilobytes
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        rss_u64.saturating_mul(1024)
    }

    // macOS: ru_maxrss is already in bytes
    #[cfg(target_os = "macos")]
    {
        rss_u64
    }

    // Unknown platform: return 0 rather than a value with unknown units.
    // Callers can check for 0 and know RSS is unavailable.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "macos"
    )))]
    {
        // Compile-time warning would be better, but this is the fallback
        let _ = rss_u64;
        0
    }
}

/// Internal implementation of getrusage.
#[cfg(unix)]
fn rusage_impl(who: libc::c_int) -> ProcUsage {
    debug_assert!(
        who == libc::RUSAGE_SELF || who == libc::RUSAGE_CHILDREN,
        "rusage_impl called with invalid who: {}",
        who
    );

    // SAFETY: zeroed rusage is valid, and we handle error return.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        let rc = libc::getrusage(who, &mut ru);

        if rc != 0 {
            return ProcUsage::default();
        }

        let result = ProcUsage {
            user_time: timeval_to_duration(ru.ru_utime),
            sys_time: timeval_to_duration(ru.ru_stime),
            max_rss_bytes: maxrss_to_bytes(ru.ru_maxrss),
        };

        // Postcondition: times should be monotonic with process lifetime.
        // We can't check that here, but we can check they're not absurd.
        // Max process lifetime ~= seconds since epoch as a sanity bound.
        debug_assert!(
            result.user_time.as_secs() < 10_000_000_000,
            "user_time sanity check failed"
        );
        debug_assert!(
            result.sys_time.as_secs() < 10_000_000_000,
            "sys_time sanity check failed"
        );

        result
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Returns resource usage for the current process.
///
/// Uses `getrusage(RUSAGE_SELF)` on Unix systems.
/// Returns `ProcUsage::default()` on failure or non-Unix.
#[cfg(unix)]
#[inline]
pub fn rusage_self() -> ProcUsage {
    rusage_impl(libc::RUSAGE_SELF)
}

/// Non-Unix fallback: returns default (zero) values.
#[cfg(not(unix))]
pub fn rusage_self() -> ProcUsage {
    ProcUsage::default()
}

/// Returns resource usage for waited-on children.
///
/// # Warning: Limited Usefulness
///
/// This function has significant limitations:
///
/// 1. **RSS is cumulative high-water mark**: Reports the largest RSS of any
///    child ever waited on, not per-job or combined peak. In a long-running
///    scheduler, this is useless for per-job memory accounting.
///
/// 2. **CPU time is cumulative**: Reports sum of all waited-on children's
///    CPU time since process start.
///
/// # When to Use
///
/// - One-shot processes that fork a single job and exit
/// - Coarse "total child CPU" accounting where per-job breakdown isn't needed
///
/// # When NOT to Use
///
/// - Per-job memory accounting in a persistent scheduler (use cgroups instead)
/// - Any scenario where you need to attribute resources to specific children
///
/// For the secret scanning scheduler (thread-based, not fork-based), this
/// function is not needed. It's provided for completeness.
#[cfg(unix)]
#[inline]
pub fn rusage_children() -> ProcUsage {
    rusage_impl(libc::RUSAGE_CHILDREN)
}

#[cfg(not(unix))]
pub fn rusage_children() -> ProcUsage {
    ProcUsage::default()
}

// ============================================================================
// Display formatting for reports
// ============================================================================

impl std::fmt::Display for ProcUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "user={:.3}s sys={:.3}s rss={}",
            self.user_time.as_secs_f64(),
            self.sys_time.as_secs_f64(),
            format_bytes(self.max_rss_bytes)
        )
    }
}

impl std::fmt::Display for ProcUsageDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "user={:.3}s sys={:.3}s rss={}",
            self.user_time.as_secs_f64(),
            self.sys_time.as_secs_f64(),
            format_bytes(self.ending_max_rss_bytes)
        )
    }
}

/// Formats bytes in human-readable form (KiB, MiB, GiB).
///
/// Note: This allocates a String. Use only for display/logging,
/// not in hot paths.
fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;

    if bytes >= GIB {
        format!("{:.2}GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2}MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2}KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{}B", bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic functionality
    // ========================================================================

    #[test]
    fn default_is_zero() {
        let usage = ProcUsage::default();
        assert_eq!(usage.user_time, Duration::ZERO);
        assert_eq!(usage.sys_time, Duration::ZERO);
        assert_eq!(usage.max_rss_bytes, 0);

        let delta = ProcUsageDelta::default();
        assert_eq!(delta.user_time, Duration::ZERO);
        assert_eq!(delta.sys_time, Duration::ZERO);
        assert_eq!(delta.ending_max_rss_bytes, 0);
    }

    #[test]
    #[cfg(unix)]
    fn rusage_self_returns_nonzero_for_running_process() {
        // A running process should have consumed *some* CPU time
        // Do some work to ensure measurable time
        let mut sum = 0u64;
        for i in 0..100_000 {
            sum = sum.wrapping_add(i);
        }
        std::hint::black_box(sum);

        let usage = rusage_self();
        // At minimum, total CPU should be non-negative (trivially true but
        // verifies we got valid data back)
        let total = usage.total_cpu_time();

        // RSS should be positive for any real process
        // (unless we're on an unsupported platform that returns 0)
        #[cfg(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        assert!(
            usage.max_rss_bytes > 0,
            "RSS should be positive on supported platforms"
        );

        let _ = total; // Use the variable
    }

    // ========================================================================
    // Delta calculations
    // ========================================================================

    #[test]
    fn delta_calculation_normal() {
        let earlier = ProcUsage {
            user_time: Duration::from_millis(100),
            sys_time: Duration::from_millis(50),
            max_rss_bytes: 1024 * 1024,
        };
        let later = ProcUsage {
            user_time: Duration::from_millis(250),
            sys_time: Duration::from_millis(80),
            max_rss_bytes: 2 * 1024 * 1024,
        };

        let delta = later.since(&earlier);
        assert_eq!(delta.user_time, Duration::from_millis(150));
        assert_eq!(delta.sys_time, Duration::from_millis(30));
        // RSS is the ending value, NOT a delta
        assert_eq!(delta.ending_max_rss_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn delta_saturates_on_backwards_time() {
        // Edge case: if somehow earlier > later (shouldn't happen but defensive)
        let earlier = ProcUsage {
            user_time: Duration::from_millis(100),
            sys_time: Duration::from_millis(50),
            max_rss_bytes: 0,
        };
        let later = ProcUsage {
            user_time: Duration::from_millis(50), // Less than earlier
            sys_time: Duration::from_millis(50),
            max_rss_bytes: 0,
        };

        let delta = later.since(&earlier);
        assert_eq!(delta.user_time, Duration::ZERO); // Saturates, doesn't underflow
    }

    #[test]
    fn total_cpu_time_saturates() {
        let delta = ProcUsageDelta {
            user_time: Duration::from_secs(u64::MAX / 2 + 1),
            sys_time: Duration::from_secs(u64::MAX / 2 + 1),
            ending_max_rss_bytes: 0,
        };
        // Should saturate to MAX, not overflow/panic
        let total = delta.total_cpu_time();
        assert!(total >= Duration::from_secs(u64::MAX / 2));
    }

    // ========================================================================
    // timeval conversion edge cases
    // ========================================================================

    #[test]
    #[cfg(unix)]
    fn timeval_negative_seconds_clamps_to_zero() {
        let tv = libc::timeval {
            tv_sec: -5,
            tv_usec: 500_000,
        };
        let d = timeval_to_duration(tv);
        // Negative seconds â†’ 0 seconds, but usec still added
        assert_eq!(d, Duration::from_micros(500_000));
    }

    #[test]
    #[cfg(unix)]
    fn timeval_negative_usec_clamps_to_zero() {
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: -100,
        };
        let d = timeval_to_duration(tv);
        assert_eq!(d, Duration::from_secs(1)); // usec clamped to 0
    }

    #[test]
    #[cfg(unix)]
    fn timeval_large_usec_clamps() {
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 2_000_000, // Invalid: should be < 1_000_000
        };
        let d = timeval_to_duration(tv);
        // Should clamp to 999_999 usec
        assert_eq!(d, Duration::from_secs(1) + Duration::from_micros(999_999));
    }

    #[test]
    #[cfg(unix)]
    fn timeval_both_negative_gives_zero() {
        let tv = libc::timeval {
            tv_sec: -1,
            tv_usec: -1,
        };
        let d = timeval_to_duration(tv);
        assert_eq!(d, Duration::ZERO);
    }

    // ========================================================================
    // maxrss conversion
    // ========================================================================

    #[test]
    #[cfg(unix)]
    fn maxrss_negative_gives_zero() {
        assert_eq!(maxrss_to_bytes(-100), 0);
        assert_eq!(maxrss_to_bytes(0), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn maxrss_linux_converts_kib_to_bytes() {
        // Linux: ru_maxrss is in KiB
        assert_eq!(maxrss_to_bytes(1024), 1024 * 1024); // 1 MiB
        assert_eq!(maxrss_to_bytes(100), 100 * 1024); // 100 KiB
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn maxrss_macos_is_already_bytes() {
        // macOS: ru_maxrss is already in bytes
        assert_eq!(maxrss_to_bytes(1024 * 1024), 1024 * 1024); // 1 MiB stays 1 MiB
    }

    // ========================================================================
    // Monotonicity invariant
    // ========================================================================

    #[test]
    #[cfg(unix)]
    fn rusage_monotonic_over_work() {
        let before = rusage_self();

        // Do substantial work
        let mut v = Vec::with_capacity(10000);
        for i in 0..10000 {
            v.push(i * i);
        }
        std::hint::black_box(&v);

        let after = rusage_self();

        // CPU time should be monotonically non-decreasing
        assert!(
            after.user_time >= before.user_time,
            "user_time went backwards: {:?} -> {:?}",
            before.user_time,
            after.user_time
        );
        assert!(
            after.sys_time >= before.sys_time,
            "sys_time went backwards: {:?} -> {:?}",
            before.sys_time,
            after.sys_time
        );
        // RSS is high-water mark, should never decrease
        assert!(
            after.max_rss_bytes >= before.max_rss_bytes,
            "max_rss went backwards: {} -> {}",
            before.max_rss_bytes,
            after.max_rss_bytes
        );
    }

    // ========================================================================
    // Display formatting
    // ========================================================================

    #[test]
    fn format_bytes_various_sizes() {
        assert_eq!(format_bytes(0), "0B");
        assert_eq!(format_bytes(512), "512B");
        assert_eq!(format_bytes(1024), "1.00KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00GiB");
        assert_eq!(format_bytes(1536 * 1024), "1.50MiB");
    }

    #[test]
    fn proc_usage_display_contains_fields() {
        let usage = ProcUsage {
            user_time: Duration::from_millis(1234),
            sys_time: Duration::from_millis(567),
            max_rss_bytes: 10 * 1024 * 1024,
        };
        let s = format!("{}", usage);
        assert!(s.contains("user="), "missing user field: {}", s);
        assert!(s.contains("sys="), "missing sys field: {}", s);
        assert!(s.contains("rss="), "missing rss field: {}", s);
        assert!(s.contains("MiB"), "should show MiB for 10MB: {}", s);
    }

    #[test]
    fn proc_usage_delta_display_uses_ending_rss() {
        let delta = ProcUsageDelta {
            user_time: Duration::from_secs(1),
            sys_time: Duration::from_secs(0),
            ending_max_rss_bytes: 50 * 1024 * 1024,
        };
        let s = format!("{}", delta);
        assert!(s.contains("rss="), "missing rss field: {}", s);
        assert!(s.contains("MiB"), "should show MiB: {}", s);
    }
}
