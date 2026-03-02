//! Blocking Token Budget for In-Flight Object Caps
//!
//! # Purpose
//!
//! Provides backpressure at discovery/scheduling time by limiting
//! the number of in-flight objects. When the cap is reached, the
//! discovery thread blocks until permits are released.
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: blocked acquires resume when permits are released
//! - **Leak-free**: `CountPermit` is RAII; permits auto-release on drop
//! - **Bounded**: total outstanding permits never exceeds capacity
//! - **No over-release**: debug_assert on release detects double-free bugs
//!
//! # Performance Characteristics
//!
//! | Operation      | Cost                    |
//! |----------------|-------------------------|
//! | try_acquire()  | Lock + check + unlock   |
//! | acquire()      | Lock + condvar wait     |
//! | release()      | Lock + notify_all       |
//!
//! This is appropriate for file-level backpressure (thousands/sec),
//! NOT for chunk-level (millions/sec). For chunk-level, use lock-free
//! `ByteBudget` or `TsBufferPool`.
//!
//! # Usage
//!
//! ```ignore
//! let budget = CountBudget::new(256); // max 256 in-flight files
//!
//! // Discovery thread
//! for path in walk_files(root) {
//!     let permit = budget.acquire(1); // blocks if at capacity
//!     executor.spawn(ScanTask { path, _permit: permit });
//! }
//!
//! // Worker thread (permit drops when task completes)
//! fn scan_task(task: ScanTask, ctx: &mut WorkerCtx) {
//!     // ... scan file ...
//!     // task._permit drops here, releasing the permit
//! }
//! ```
//!
//! # Design Notes
//!
//! - Uses Mutex + Condvar (not atomics) because:
//!   - Discovery is already I/O-bound on directory traversal
//!   - Simple, correct, no subtle memory ordering bugs
//!   - Condvar provides efficient blocking (no spin-wait)
//!
//! - `forget()` allows transferring ownership to another mechanism
//!   (e.g., if you need to split a permit across phases)

use std::sync::{Arc, Condvar, Mutex};

/// Internal state protected by mutex.
#[derive(Debug)]
struct State {
    /// Currently available permits.
    avail: usize,
}

/// Fixed-capacity, blocking token budget.
///
/// Use for "in-flight objects" / "queued work" caps where the producer thread
/// should block rather than spin when at capacity.
///
/// # Thread Safety
///
/// Safe to share across threads via `Arc<CountBudget>`.
/// Typically: one discovery thread calling `acquire()`,
/// multiple worker threads dropping `CountPermit`.
///
/// # Correctness Notes
///
/// - Uses `notify_all()` on release to handle variable `n` requests correctly
/// - Poison-tolerant in Drop paths to avoid process abort on double panic
#[derive(Debug)]
pub struct CountBudget {
    /// Total capacity (immutable after construction).
    total: usize,
    /// Mutable state.
    state: Mutex<State>,
    /// Condition variable for blocking acquire.
    cv: Condvar,
}

impl CountBudget {
    /// Lock state with poison recovery.
    ///
    /// Used in Drop paths where we must not panic (risk of process abort).
    /// If the mutex was poisoned by a prior panic, we recover the inner state
    /// and continue - the alternative (panic in Drop) is worse.
    #[inline]
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poison) => {
                // Mutex was poisoned by a panic in another thread.
                // Recover the state - we still need to release permits.
                poison.into_inner()
            }
        }
    }
}

impl CountBudget {
    /// Create a new budget with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `total` is 0.
    pub fn new(total: usize) -> Arc<Self> {
        assert!(total > 0, "CountBudget capacity must be > 0");
        Arc::new(Self {
            total,
            state: Mutex::new(State { avail: total }),
            cv: Condvar::new(),
        })
    }

    /// Total capacity of this budget.
    #[inline]
    pub fn total(&self) -> usize {
        self.total
    }

    /// Current available permits.
    ///
    /// # Note
    ///
    /// This is a snapshot and may be stale by the time you use it.
    /// For coordination, use `acquire()` or `try_acquire()`.
    #[inline]
    pub fn available(&self) -> usize {
        self.state.lock().expect("CountBudget mutex poisoned").avail
    }

    /// Current in-use permits (total - available).
    #[inline]
    pub fn in_use(&self) -> usize {
        let avail = self.available();
        self.total.saturating_sub(avail)
    }

    /// Try to acquire `n` permits without blocking.
    ///
    /// Returns `Some(permit)` if successful, `None` if insufficient permits.
    ///
    /// # Panics
    ///
    /// - Panics if `n` is 0
    /// - Panics if `n > total` (cannot satisfy)
    pub fn try_acquire(self: &Arc<Self>, n: usize) -> Option<CountPermit> {
        assert!(n > 0, "cannot acquire 0 permits");
        assert!(
            n <= self.total,
            "cannot acquire {} permits from budget of {}",
            n,
            self.total
        );

        let mut st = self.state.lock().expect("CountBudget mutex poisoned");
        if st.avail < n {
            return None;
        }
        st.avail -= n;
        Some(CountPermit {
            budget: Arc::clone(self),
            n,
            active: true,
        })
    }

    /// Acquire `n` permits, blocking until available.
    ///
    /// # Panics
    ///
    /// - Panics if `n` is 0
    /// - Panics if `n > total` (would deadlock)
    /// - Panics if mutex is poisoned
    pub fn acquire(self: &Arc<Self>, n: usize) -> CountPermit {
        assert!(n > 0, "cannot acquire 0 permits");
        assert!(
            n <= self.total,
            "cannot acquire {} permits from budget of {} (would deadlock)",
            n,
            self.total
        );

        let mut st = self.state.lock().expect("CountBudget mutex poisoned");
        while st.avail < n {
            st = self.cv.wait(st).expect("CountBudget condvar poisoned");
        }
        st.avail -= n;

        CountPermit {
            budget: Arc::clone(self),
            n,
            active: true,
        }
    }

    /// Acquire with timeout.
    ///
    /// Returns `Some(permit)` if acquired within the timeout, `None` otherwise.
    ///
    /// # Panics
    ///
    /// Same as `acquire()`.
    pub fn acquire_timeout(
        self: &Arc<Self>,
        n: usize,
        timeout: std::time::Duration,
    ) -> Option<CountPermit> {
        assert!(n > 0, "cannot acquire 0 permits");
        assert!(
            n <= self.total,
            "cannot acquire {} permits from budget of {}",
            n,
            self.total
        );

        let mut st = self.state.lock().expect("CountBudget mutex poisoned");
        let deadline = std::time::Instant::now() + timeout;

        while st.avail < n {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (new_st, timeout_result) = self
                .cv
                .wait_timeout(st, remaining)
                .expect("CountBudget condvar poisoned");
            st = new_st;
            if timeout_result.timed_out() && st.avail < n {
                return None;
            }
        }

        st.avail -= n;
        Some(CountPermit {
            budget: Arc::clone(self),
            n,
            active: true,
        })
    }

    /// Internal: release `n` permits back to the pool.
    ///
    /// Called by `CountPermit::drop()`.
    ///
    /// # Safety Notes
    ///
    /// - Uses `lock_or_recover()` to avoid panic in Drop paths
    /// - Uses `notify_all()` to handle variable `n` correctly (prevents stranded waiters)
    /// - Guards invariant check against double-panic
    fn release(&self, n: usize) {
        let mut st = self.lock_or_recover();
        st.avail += n;

        // Invariant check: should never exceed total.
        // Guard against panic during unwinding (would cause process abort).
        #[cfg(debug_assertions)]
        {
            if st.avail > self.total && !std::thread::panicking() {
                panic!(
                    "CountBudget over-release: avail={} > total={}",
                    st.avail, self.total
                );
            }
        }

        // Drop lock before notifying to reduce contention
        drop(st);

        // Use notify_all() to prevent "stranded waiter" deadlock.
        //
        // Scenario with notify_one() + variable n:
        //   - Waiter A needs 5, Waiter B needs 1, avail=0
        //   - release(1) wakes A, A sees 1<5, re-waits
        //   - B sleeps forever despite sufficient permits
        //
        // notify_all() cost is negligible for file-level backpressure
        // (thousands/sec, not millions/sec).
        self.cv.notify_all();
    }

    /// Release all permits and wake all waiters.
    ///
    /// Useful for shutdown: any blocked acquire() will proceed and
    /// can then check a shutdown flag.
    ///
    /// # Warning
    ///
    /// This resets the budget to full capacity. Any outstanding permits
    /// will cause over-release on drop. Only call this during shutdown
    /// when you're sure no permits are outstanding.
    pub fn release_all_and_wake(&self) {
        let mut st = self.lock_or_recover();
        st.avail = self.total;
        drop(st);
        self.cv.notify_all();
    }
}

/// RAII permit for `CountBudget`.
///
/// Automatically releases permits back to the budget on drop.
///
/// # Leak Prevention
///
/// - Moving into a struct that gets dropped: permits released
/// - Panic during task: permits released (Drop runs during unwinding)
/// - Explicit drop: permits released
/// - `forget()`: permits intentionally leaked (for ownership transfer)
#[derive(Debug)]
#[must_use = "CountPermit releases on drop; not holding it defeats backpressure"]
pub struct CountPermit {
    budget: Arc<CountBudget>,
    n: usize,
    active: bool,
}

impl CountPermit {
    /// Number of permits held by this guard.
    #[inline]
    pub fn count(&self) -> usize {
        if self.active {
            self.n
        } else {
            0
        }
    }

    /// Intentionally leak these permits (don't release on drop).
    ///
    /// Returns the number of permits leaked, allowing the caller to
    /// track them if needed (e.g., for manual release elsewhere).
    ///
    /// # Warning
    ///
    /// You are responsible for eventually releasing these permits
    /// via another `CountPermit` or explicit accounting. Leaked permits
    /// permanently reduce effective capacity until the budget is dropped.
    pub fn forget(mut self) -> usize {
        self.active = false;
        self.n
    }

    /// Split off `count` permits into a new permit.
    ///
    /// This permit retains `self.n - count` permits.
    /// Returns a new permit with `count` permits.
    ///
    /// # Panics
    ///
    /// Panics if `count > self.n`, `count == 0`, or the permit is inactive
    /// (i.e., already consumed via [`forget`](Self::forget)).
    pub fn split(&mut self, count: usize) -> CountPermit {
        assert!(count > 0, "cannot split 0 permits");
        assert!(
            count <= self.n,
            "cannot split {} from permit with {} permits",
            count,
            self.n
        );
        assert!(self.active, "cannot split inactive permit");

        self.n -= count;
        CountPermit {
            budget: Arc::clone(&self.budget),
            n: count,
            active: true,
        }
    }
}

impl Drop for CountPermit {
    fn drop(&mut self) {
        if self.active && self.n > 0 {
            self.budget.release(self.n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn basic_acquire_release() {
        let b = CountBudget::new(10);
        assert_eq!(b.total(), 10);
        assert_eq!(b.available(), 10);
        assert_eq!(b.in_use(), 0);

        let p1 = b.acquire(3);
        assert_eq!(b.available(), 7);
        assert_eq!(b.in_use(), 3);
        assert_eq!(p1.count(), 3);

        let p2 = b.acquire(2);
        assert_eq!(b.available(), 5);
        assert_eq!(b.in_use(), 5);

        drop(p1);
        assert_eq!(b.available(), 8);
        assert_eq!(b.in_use(), 2);

        drop(p2);
        assert_eq!(b.available(), 10);
        assert_eq!(b.in_use(), 0);
    }

    #[test]
    fn try_acquire_success() {
        let b = CountBudget::new(5);

        let p1 = b.try_acquire(3);
        assert!(p1.is_some());
        assert_eq!(b.available(), 2);

        let p2 = b.try_acquire(2);
        assert!(p2.is_some());
        assert_eq!(b.available(), 0);
    }

    #[test]
    fn try_acquire_insufficient() {
        let b = CountBudget::new(5);

        let _p1 = b.acquire(3);
        assert_eq!(b.available(), 2);

        // Not enough permits
        let p2 = b.try_acquire(3);
        assert!(p2.is_none());
        assert_eq!(b.available(), 2); // Unchanged
    }

    #[test]
    fn blocking_acquire_releases_when_available() {
        let b = CountBudget::new(1);
        let p1 = b.acquire(1);

        let hit = Arc::new(AtomicBool::new(false));
        let hit2 = Arc::clone(&hit);
        let b2 = Arc::clone(&b);

        let th = thread::spawn(move || {
            // This should block until p1 is dropped
            let _p2 = b2.acquire(1);
            hit2.store(true, Ordering::SeqCst);
        });

        // Give the thread time to start and block
        thread::sleep(Duration::from_millis(50));
        assert!(!hit.load(Ordering::SeqCst), "should still be blocked");

        // Release permit
        drop(p1);

        // Now the thread should proceed
        th.join().unwrap();
        assert!(hit.load(Ordering::SeqCst), "should have acquired");
        assert_eq!(b.available(), 1);
    }

    #[test]
    fn acquire_timeout_success() {
        let b = CountBudget::new(5);
        let p = b.acquire_timeout(3, Duration::from_secs(1));
        assert!(p.is_some());
        assert_eq!(b.available(), 2);
    }

    #[test]
    fn acquire_timeout_failure() {
        let b = CountBudget::new(1);
        let _p1 = b.acquire(1);

        // Should timeout
        let start = std::time::Instant::now();
        let p2 = b.acquire_timeout(1, Duration::from_millis(50));
        let elapsed = start.elapsed();

        assert!(p2.is_none());
        assert!(elapsed >= Duration::from_millis(40)); // Allow some slack
    }

    #[test]
    fn permit_forget() {
        let b = CountBudget::new(5);

        let p = b.acquire(3);
        assert_eq!(b.available(), 2);

        let leaked = p.forget();
        assert_eq!(leaked, 3); // Returns count of leaked permits
                               // Permits should NOT be released
        assert_eq!(b.available(), 2);
    }

    #[test]
    fn permit_split() {
        let b = CountBudget::new(10);

        let mut p1 = b.acquire(6);
        assert_eq!(p1.count(), 6);
        assert_eq!(b.available(), 4);

        let p2 = p1.split(2);
        assert_eq!(p1.count(), 4);
        assert_eq!(p2.count(), 2);
        assert_eq!(b.available(), 4); // No change - just split ownership

        drop(p2);
        assert_eq!(b.available(), 6); // p2's 2 permits returned

        drop(p1);
        assert_eq!(b.available(), 10); // All returned
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn zero_capacity_panics() {
        let _b = CountBudget::new(0);
    }

    #[test]
    #[should_panic(expected = "cannot acquire 0 permits")]
    fn acquire_zero_panics() {
        let b = CountBudget::new(5);
        let _p = b.acquire(0);
    }

    #[test]
    #[should_panic(expected = "cannot acquire 10 permits from budget of 5")]
    fn acquire_more_than_total_panics() {
        let b = CountBudget::new(5);
        let _p = b.acquire(10);
    }

    #[test]
    fn concurrent_acquire_release_stress() {
        let b = CountBudget::new(10);
        let acquired = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..8)
            .map(|_| {
                let b = Arc::clone(&b);
                let acquired = Arc::clone(&acquired);
                let released = Arc::clone(&released);

                thread::spawn(move || {
                    for _ in 0..100 {
                        let p = b.acquire(1);
                        acquired.fetch_add(1, Ordering::Relaxed);
                        // Simulate some work
                        thread::yield_now();
                        drop(p);
                        released.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for th in threads {
            th.join().unwrap();
        }

        assert_eq!(acquired.load(Ordering::Relaxed), 800);
        assert_eq!(released.load(Ordering::Relaxed), 800);
        assert_eq!(b.available(), 10);
    }

    /// Verify no lost permits on panic during task.
    #[test]
    fn permit_released_on_panic() {
        use std::panic;

        let b = CountBudget::new(5);
        let p = b.acquire(3);
        assert_eq!(b.available(), 2);

        let result = panic::catch_unwind(panic::AssertUnwindSafe(move || {
            let _p = p; // Move permit into closure
            panic!("intentional panic");
        }));

        assert!(result.is_err());
        // Permit should have been released during unwinding
        assert_eq!(b.available(), 5);
    }

    #[test]
    fn multiple_waiters_all_proceed() {
        let b = CountBudget::new(1);
        let _p = b.acquire(1); // Hold the only permit

        let completed = Arc::new(AtomicUsize::new(0));

        // Spawn 5 threads all waiting for the permit
        let threads: Vec<_> = (0..5)
            .map(|_| {
                let b = Arc::clone(&b);
                let completed = Arc::clone(&completed);
                thread::spawn(move || {
                    let _p = b.acquire(1);
                    completed.fetch_add(1, Ordering::SeqCst);
                    // Hold briefly
                    thread::sleep(Duration::from_millis(10));
                    // Release on drop
                })
            })
            .collect();

        // Give threads time to start and block
        thread::sleep(Duration::from_millis(50));
        assert_eq!(completed.load(Ordering::SeqCst), 0);

        // Release the permit - threads should proceed one by one
        drop(_p);

        // Wait for all threads
        for th in threads {
            th.join().unwrap();
        }

        assert_eq!(completed.load(Ordering::SeqCst), 5);
        assert_eq!(b.available(), 1);
    }

    /// Test that variable `n` requests don't cause "stranded waiter" deadlock.
    ///
    /// This scenario would deadlock with `notify_one()`:
    /// - Thread A wants 5 permits, Thread B wants 1
    /// - Only 1 permit released
    /// - With notify_one: A wakes, sees 1<5, re-sleeps; B never wakes
    /// - With notify_all: Both wake, B proceeds, A re-sleeps correctly
    #[test]
    fn variable_n_no_stranded_waiter() {
        let b = CountBudget::new(5);

        // Take all permits
        let mut p5 = b.acquire(5);
        assert_eq!(b.available(), 0);

        let b_clone1 = Arc::clone(&b);
        let b_clone2 = Arc::clone(&b);

        let thread_a_done = Arc::new(AtomicBool::new(false));
        let thread_b_done = Arc::new(AtomicBool::new(false));
        let a_done = Arc::clone(&thread_a_done);
        let b_done = Arc::clone(&thread_b_done);

        // Thread A: wants 4 permits (won't be satisfied by release of 1)
        let thread_a = thread::spawn(move || {
            let _p = b_clone1.acquire(4);
            a_done.store(true, Ordering::SeqCst);
        });

        // Thread B: wants 1 permit (will be satisfied by release of 1)
        let thread_b = thread::spawn(move || {
            let _p = b_clone2.acquire(1);
            b_done.store(true, Ordering::SeqCst);
        });

        // Let both threads block
        thread::sleep(Duration::from_millis(50));
        assert!(!thread_a_done.load(Ordering::SeqCst));
        assert!(!thread_b_done.load(Ordering::SeqCst));

        // Release 1 permit - B should proceed even if A wakes first
        let p1 = p5.split(1);
        drop(p1); // Release the 1 permit

        // Wait for B to complete (should happen quickly)
        thread::sleep(Duration::from_millis(100));
        assert!(
            thread_b_done.load(Ordering::SeqCst),
            "Thread B should have acquired 1 permit"
        );

        // A is still waiting for 4, but we only have 0 available
        assert!(!thread_a_done.load(Ordering::SeqCst));

        // Now release the remaining 4
        drop(p5);

        // Both threads should complete
        thread_a.join().unwrap();
        thread_b.join().unwrap();

        assert!(thread_a_done.load(Ordering::SeqCst));
        assert_eq!(b.available(), 5);
    }
}
