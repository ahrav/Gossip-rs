//! Thread-local worker ID for per-worker fast path routing.
//!
//! # Purpose
//!
//! This module enables O(1) per-worker routing for buffer pool returns:
//! - Worker threads set their ID at startup via `set_current_worker_id(Some(id))`
//! - Buffer pool `release()` checks TLS to route to local queue first
//! - Non-worker threads (I/O completions) fall back to global queue
//!
//! # Safety
//!
//! Workers must clear TLS before exit to prevent mis-routing during thread teardown:
//! ```ignore
//! worker_id::set_current_worker_id(Some(worker_id)); // on startup
//! // ... work ...
//! worker_id::set_current_worker_id(None); // before exit
//! ```
//!
//! # Correctness Invariant
//!
//! `current_worker_id()` returns `Some(id)` **only** on active executor worker threads.
//! Any other thread (main, I/O, tests) sees `None`.

use std::cell::Cell;

/// Sentinel value indicating no worker ID is set.
///
/// # Why `usize::MAX`?
///
/// - **Not a valid worker ID**: No executor will have 2^64 workers.
/// - **Branchless comparison**: `id == NO_WORKER` compiles to a single `cmp`.
/// - **No `Option` overhead**: Avoids the 1-byte discriminant + padding that
///   `Option<usize>` would add in TLS (minor, but TLS access is already slow).
///
/// Trade-off: Caller must not pass `usize::MAX` as a worker ID. This is enforced
/// by the executor (worker IDs are sequential from 0).
const NO_WORKER: usize = usize::MAX;

thread_local! {
    /// Per-thread worker ID storage.
    ///
    /// Initialized to `NO_WORKER` (not a worker thread). Callers that create
    /// worker threads should set this to the actual worker ID before entering
    /// the work loop, and clear it on exit.
    ///
    /// # Initialization Timing
    ///
    /// The `const { ... }` initializer means no runtime init code runs—the value
    /// is baked into the binary. First access on any thread sees `NO_WORKER`.
    static WORKER_ID: Cell<usize> = const { Cell::new(NO_WORKER) };
}

/// Set current worker ID for this thread.
///
/// Worker threads should call this once at startup with `Some(id)` and
/// once at exit with `None`.
///
/// # Performance
///
/// Single thread-local write. No atomics, no syscalls.
#[inline]
pub fn set_current_worker_id(id: Option<usize>) {
    WORKER_ID.with(|c| c.set(id.unwrap_or(NO_WORKER)));
}

/// Get current worker ID for this thread, if any.
///
/// Returns `Some(id)` only on active executor worker threads.
/// Returns `None` on main thread, I/O threads, test threads, etc.
///
/// # Performance
///
/// Single thread-local read. No atomics, no syscalls.
#[inline]
pub fn current_worker_id() -> Option<usize> {
    WORKER_ID.with(|c| {
        let v = c.get();
        if v == NO_WORKER {
            None
        } else {
            Some(v)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn default_is_none() {
        // Fresh thread should have no worker ID
        assert_eq!(current_worker_id(), None);
    }

    #[test]
    fn set_and_get() {
        set_current_worker_id(Some(42));
        assert_eq!(current_worker_id(), Some(42));

        set_current_worker_id(Some(7));
        assert_eq!(current_worker_id(), Some(7));

        set_current_worker_id(None);
        assert_eq!(current_worker_id(), None);
    }

    #[test]
    fn thread_isolation() {
        set_current_worker_id(Some(0));

        let handle = thread::spawn(|| {
            // New thread should start with None
            assert_eq!(current_worker_id(), None);

            set_current_worker_id(Some(1));
            assert_eq!(current_worker_id(), Some(1));
        });

        // Original thread still has its value
        assert_eq!(current_worker_id(), Some(0));

        handle.join().unwrap();

        // Still has its value after child exits
        assert_eq!(current_worker_id(), Some(0));

        // Cleanup
        set_current_worker_id(None);
    }

    #[test]
    fn max_worker_id_works() {
        // usize::MAX - 1 should work fine (MAX itself is the sentinel)
        let max_valid = usize::MAX - 1;
        set_current_worker_id(Some(max_valid));
        assert_eq!(current_worker_id(), Some(max_valid));
        set_current_worker_id(None);
    }
}
