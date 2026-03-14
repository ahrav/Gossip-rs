//! Debug-only allocation guard toggle for Git scan hot paths.
//!
//! In release builds this is a no-op. In debug builds, when enabled, hot-path
//! sections can assert that no heap allocations occurred after warmup.
//!
//! # Notes
//! - This only affects call sites that explicitly check `enabled()`.
//! - Allocation guards may false-positive if other threads allocate.
//! - Tests install `CountingAllocator` to make allocation tracking visible.
//! - The enable flag is thread-local, but allocation counters are global.
//!   Enable the guard only around code that is expected to be allocation-free.

#[cfg(debug_assertions)]
use std::cell::Cell;

#[cfg(debug_assertions)]
thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
}

/// Returns true when the debug allocation guard is enabled.
///
/// In release builds this always returns false.
#[must_use]
pub fn enabled() -> bool {
    #[cfg(debug_assertions)]
    {
        ENABLED.with(|flag| flag.get())
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Enables or disables the debug allocation guard.
///
/// In release builds this is a no-op.
pub fn set_enabled(enabled: bool) {
    #[cfg(debug_assertions)]
    {
        ENABLED.with(|flag| flag.set(enabled));
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = enabled;
    }
}

#[cfg(test)]
#[global_allocator]
static GLOBAL_ALLOC: scanner_scheduler::CountingAllocator = scanner_scheduler::CountingAllocator;
