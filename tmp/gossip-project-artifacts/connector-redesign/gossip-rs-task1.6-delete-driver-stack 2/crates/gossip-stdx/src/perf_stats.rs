//! Small arithmetic helpers for scan-time counters.
//!
//! These helpers centralize saturating/max/set update patterns so
//! hot paths stay concise and consistent.
//! They only mutate counters when
//! `all(feature = "perf-stats", debug_assertions)` is enabled; otherwise all
//! helpers compile to no-ops.
//!
//! # Invariants
//!
//! - Counter updates are infallible and never panic.
//! - Call sites can stay unconditional in hot paths; instrumentation is removed
//!   entirely outside debug perf-stats builds.
//!
//! # Why wrapping vs. saturating?
//!
//! * **`sat_add_*`** — most counters: clamping at `MAX` is safer than silent
//!   wrap-around for values displayed to operators.
//! * **`max_*`** — high-water-mark tracking (peak in-flight bytes, max depth).
//! * **`set_*`** — final-value assignment (e.g. total op counts known after a
//!   batch completes).

/// Saturating add for a `u64` counter.
///
/// In instrumented builds this keeps monotonic counters from wrapping through
/// zero. In non-instrumented builds this is an intentional no-op.
#[inline(always)]
pub fn sat_add_u64(counter: &mut u64, delta: u64) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.saturating_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// Saturating add for a `u32` counter.
#[inline(always)]
pub fn sat_add_u32(counter: &mut u32, delta: u32) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.saturating_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// Saturating add for a `usize` counter.
#[inline(always)]
pub fn sat_add_usize(counter: &mut usize, delta: usize) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = counter.saturating_add(delta);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, delta);
    }
}

/// High-water-mark update for a `u64` counter.
///
/// Stores the larger of `*counter` and `value`; no-op when instrumentation is
/// disabled.
#[inline(always)]
pub fn max_u64(counter: &mut u64, value: u64) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = (*counter).max(value);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// High-water-mark update for a `u32` counter.
#[inline(always)]
pub fn max_u32(counter: &mut u32, value: u32) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = (*counter).max(value);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// High-water-mark update for a `u16` counter.
#[inline(always)]
pub fn max_u16(counter: &mut u16, value: u16) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = (*counter).max(value);
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// Unconditional assignment for a `u32` counter.
#[inline(always)]
pub fn set_u32(counter: &mut u32, value: u32) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = value;
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// Unconditional assignment for a `u64` counter.
///
/// Use when the final value is known (e.g. total op count after a batch).
/// Outside instrumented builds this is a no-op.
#[inline(always)]
pub fn set_u64(counter: &mut u64, value: u64) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = value;
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}

/// Unconditional assignment for a `usize` counter.
#[inline(always)]
pub fn set_usize(counter: &mut usize, value: usize) {
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    {
        *counter = value;
    }
    #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
    {
        let _ = (counter, value);
    }
}
