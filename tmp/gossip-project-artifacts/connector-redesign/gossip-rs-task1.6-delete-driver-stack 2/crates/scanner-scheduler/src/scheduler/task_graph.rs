//! Task Graph: Typed Task Model for Scanner Scheduler
//!
//! # Architecture
//!
//! Three task types form a DAG:
//! ```text
//! Enumerate --+--> FetchSync --+--> Scan ----> (output)
//!             |               |     `--> FetchSync (nested archive)
//!             |               `--> FetchSync (next chunk)
//!             `--> Enumerate (next cursor batch)
//! ```
//!
//! # Why Typed Tasks Over `Box<dyn FnOnce()>`
//!
//! 1. **Size**: Task enum is ~56 bytes; boxed closure is 16 bytes + heap alloc
//! 2. **Locality**: Tasks packed in deques without indirection
//! 3. **Introspection**: Can inspect pending work for metrics/debugging
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: Every enqueued object eventually scans (permits track this)
//! - **Bounded frontier**: `ObjectFrontier` caps discovered-but-not-complete objects
//! - **Leak-free**: `ObjectCtx` RAII ensures permit release when last reference drops
//! - **Non-blocking Enumerate**: Uses `try_acquire_ctx()`, re-enqueues on failure
//! - **Abort-aware**: `FailRun` policies can stop new task dispatch without leaking permits
//!
//! # Permit Lifetime via ObjectCtx
//!
//! The `ObjectCtx` pattern ensures correct permit lifetime:
//! ```text
//! FetchSync { obj: ObjectRef } --clone--> FetchSync { obj: ObjectRef }
//!                              `-clone--> Scan { obj: ObjectRef }
//!                                              `- last ref drops
//!                                                 permit released
//! ```
//!
//! The frontier slot is released exactly when the last task referencing the
//! object completes. No manual "remember to attach permit" required.
//!
//! # Performance Characteristics
//!
//! | Pattern | Overhead |
//! |---------|----------|
//! | Task dispatch | Single match + indirect call (~5ns) |
//! | ObjectRef clone | Single atomic increment (~10ns) |
//! | FetchSync chain | One Arc clone per chunk, zero path clones |

use std::path::PathBuf;
use std::sync::Arc;

use super::count_budget::{CountBudget, CountPermit};
use super::engine_stub::FileId;
use super::ts_buffer_pool::TsBufferHandle;

// Re-export contract types for convenience
pub use super::contract::{ObjectId, SourceId};

// ============================================================================
// Cursor for Enumeration Pagination
// ============================================================================

/// Opaque cursor for resumable enumeration.
///
/// # Design
///
/// Cursor is source-specific. For filesystem: could be a directory stack.
/// For S3: a continuation token. For git: a commit iterator.
///
/// # Important
///
/// This type intentionally does NOT implement Clone. Moving a cursor
/// (re-enqueueing Enumerate) is a move, not a clone. The boxed state
/// moves with it.
#[derive(Debug, Default)]
pub enum EnumCursor {
    /// Initial state - start enumeration
    #[default]
    Start,
    /// More work remains at this position
    Continue(Box<CursorState>),
    /// Enumeration complete
    Done,
}

/// Source-specific cursor state.
///
/// # Memory Considerations
///
/// For `FsDir`, the vectors hold the **current batch** of entries to process,
/// not the entire directory listing. Batch size is controlled by `ENUM_BATCH_SIZE`.
/// A single Enumerate task processes one batch and re-enqueues with updated state.
#[derive(Debug)]
pub enum CursorState {
    /// Filesystem: stack of directories to visit + current batch
    FsDir {
        /// Directories remaining to process (depth-first stack)
        dirs: Vec<PathBuf>,
        /// Current batch of entries (capped by ENUM_BATCH_SIZE)
        entries: Vec<PathBuf>,
    },
    /// Generic byte offset for streaming sources
    Offset(u64),
    /// Opaque token for paginated APIs (S3, etc.)
    Token(String),
}

// ============================================================================
// Object Context (lifetime anchor for permit + metadata)
// ============================================================================

/// Shared context for an in-flight object.
///
/// # Ownership Model
///
/// `ObjectCtx` is wrapped in `Arc` and shared by all tasks processing the same
/// object (FetchSync chain + Scan tasks). The frontier permit is released
/// exactly when the last `Arc<ObjectCtx>` drops.
///
/// # Why This Pattern
///
/// Previous design had `Option<Arc<ObjectPermit>>` in Scan which was error-prone:
/// - Easy to forget to attach permit to final scan
/// - Manual coordination of "is this the last chunk"
///
/// With ObjectCtx, correctness is automatic: the permit lives as long as any
/// task holds a reference to the object context.
#[derive(Debug)]
pub struct ObjectCtx {
    /// Object metadata (path, size hint, IDs)
    pub descriptor: ObjectDescriptor,
    /// Frontier permit - released when ObjectCtx drops.
    /// Intentionally not read; it's an RAII sentinel.
    _permit: ObjectPermit,
    /// File ID for scan engine
    pub file_id: FileId,
}

impl ObjectCtx {
    /// Create a new object context.
    ///
    /// The permit is moved into the context and will be released when
    /// the last `Arc<ObjectCtx>` drops.
    pub fn new(descriptor: ObjectDescriptor, permit: ObjectPermit, file_id: FileId) -> Self {
        Self {
            descriptor,
            _permit: permit,
            file_id,
        }
    }

    /// Path to the object (convenience accessor).
    #[inline]
    pub fn path(&self) -> &PathBuf {
        &self.descriptor.path
    }
}

/// Shared reference to an object context.
///
/// Clone is cheap (atomic increment). All tasks for the same object
/// share the same `ObjectRef`.
pub type ObjectRef = Arc<ObjectCtx>;

// ============================================================================
// Object Descriptor
// ============================================================================

/// Descriptor for a discovered object, ready for fetching.
///
/// # Size Budget
///
/// PathBuf is 24 bytes (ptr + len + cap) on 64-bit.
/// ObjectId is u64 (8 bytes), SourceId is u32 (4 bytes).
/// Total: 24 + 8 + 8 + 4 = 44 bytes (48 with padding).
#[derive(Clone, Debug)]
pub struct ObjectDescriptor {
    /// Path or URI to fetch from
    pub path: PathBuf,
    /// Size hint from discovery (may differ from actual)
    pub size_hint: u64,
    /// Object ID assigned during enumeration
    pub object_id: ObjectId,
    /// Source this object came from
    pub source_id: SourceId,
}

// ============================================================================
// Task Types
// ============================================================================

/// Task for the work-stealing executor.
///
/// # Size
///
/// Largest variant determines size. With `ObjectRef` (8 bytes) instead of
/// inline `PathBuf` (24 bytes), tasks are more compact.
///
/// # Ownership Rules
///
/// - `Enumerate`: No object context (frontier checked via try_acquire)
/// - `FetchSync`: Holds `ObjectRef` (released when all chunks done)
/// - `Scan`: Holds `ObjectRef` (same lifetime as fetch chain)
pub enum Task {
    /// Enumerate objects from a source.
    ///
    /// # Non-Blocking Requirement
    ///
    /// Enumerate MUST NOT block on frontier.acquire(). It uses try_acquire_ctx()
    /// and re-enqueues itself on failure. This prevents head-of-line deadlock
    /// when all executor threads are running Enumerate tasks.
    Enumerate {
        source_id: SourceId,
        cursor: EnumCursor,
    },

    /// Fetch next chunk from a local object (blocking read).
    ///
    /// On success: spawns Scan task, then spawns another FetchSync if more data.
    /// ObjectRef is cloned (cheap) to child tasks, permit released when all done.
    FetchSync {
        /// Shared object context (path, permit, file_id)
        obj: ObjectRef,
        /// Current file offset for next read
        offset: u64,
    },

    /// Scan a buffer of data.
    ///
    /// Runs detection engine, emits findings, returns buffer to pool.
    /// May spawn FetchSync for nested objects (archives).
    Scan {
        /// Shared object context
        obj: ObjectRef,
        /// Buffer containing data to scan
        buffer: TsBufferHandle,
        /// Absolute offset of buffer[0] in the object
        base_offset: u64,
        /// Valid bytes in buffer (u32 sufficient: BUFFER_LEN_MAX is 4MB)
        len: u32,
        /// Overlap prefix bytes (for cross-chunk dedup)
        prefix_len: u32,
    },
}

// Manual Debug impl because TsBufferHandle doesn't implement Debug
impl std::fmt::Debug for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Task::Enumerate { source_id, cursor } => f
                .debug_struct("Enumerate")
                .field("source_id", source_id)
                .field("cursor", cursor)
                .finish(),
            Task::FetchSync { obj, offset } => f
                .debug_struct("FetchSync")
                .field("path", obj.path())
                .field("file_id", &obj.file_id)
                .field("offset", offset)
                .finish(),
            Task::Scan {
                obj,
                base_offset,
                len,
                prefix_len,
                ..
            } => f
                .debug_struct("Scan")
                .field("file_id", &obj.file_id)
                .field("base_offset", base_offset)
                .field("len", len)
                .field("prefix_len", prefix_len)
                .field("buffer", &"<buffer>")
                .finish(),
        }
    }
}

// ============================================================================
// Object Frontier (Bounded Ready Set)
// ============================================================================

/// Bounded frontier for in-flight objects.
///
/// # Purpose
///
/// Prevents enumeration from exploding task queues. Discovery uses
/// `try_acquire_ctx()` before spawning FetchSync tasks; re-enqueues on failure.
///
/// # Correctness
///
/// - Work-conserving: Enumerate re-enqueues itself, never drops objects
/// - Bounded: never exceeds configured capacity
/// - Leak-free: RAII permit in ObjectCtx releases on drop
#[derive(Debug)]
pub struct ObjectFrontier {
    budget: Arc<CountBudget>,
}

impl ObjectFrontier {
    /// Create a frontier with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if capacity is 0.
    pub fn new(capacity: usize) -> Self {
        Self {
            budget: CountBudget::new(capacity),
        }
    }

    /// Try to acquire a permit for a new object.
    ///
    /// Returns `None` if frontier is at capacity. Caller should re-enqueue
    /// Enumerate task and return (non-blocking).
    ///
    /// # Usage
    ///
    /// ```ignore
    /// if let Some(permit) = frontier.try_acquire() {
    ///     let ctx = Arc::new(ObjectCtx::new(descriptor, permit, file_id));
    ///     spawn(Task::FetchSync { obj: ctx, offset: 0 });
    /// } else {
    ///     // Re-enqueue ourselves for later
    ///     spawn(Task::Enumerate { source_id, cursor });
    /// }
    /// ```
    #[inline]
    pub fn try_acquire(&self) -> Option<ObjectPermit> {
        self.budget
            .try_acquire(1)
            .map(|inner| ObjectPermit { _inner: inner })
    }

    /// Try to acquire and wrap in ObjectCtx in one step.
    ///
    /// This is the preferred API for Enumerate tasks. Returns None if
    /// frontier is at capacity.
    pub fn try_acquire_ctx(
        &self,
        descriptor: ObjectDescriptor,
        file_id: FileId,
    ) -> Option<ObjectRef> {
        self.try_acquire()
            .map(|permit| Arc::new(ObjectCtx::new(descriptor, permit, file_id)))
    }

    /// Acquire a permit, blocking until available.
    ///
    /// # Warning
    ///
    /// DO NOT call this from tasks running on the executor. Use `try_acquire()`
    /// and re-enqueue on failure. Blocking acquire from executor threads can
    /// cause deadlock if all threads block while permits are held by queued tasks.
    ///
    /// This is safe to call from:
    /// - A dedicated discovery thread (not on the executor)
    /// - External callers before starting the executor
    #[inline]
    pub fn acquire(&self) -> ObjectPermit {
        let inner = self.budget.acquire(1);
        ObjectPermit { _inner: inner }
    }

    /// Current number of in-flight objects.
    #[inline]
    pub fn in_flight(&self) -> usize {
        self.budget.in_use()
    }

    /// Total capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.budget.total()
    }

    /// Available slots.
    #[inline]
    pub fn available(&self) -> usize {
        self.budget.available()
    }
}

/// RAII permit for an in-flight object.
///
/// Typically wrapped inside `ObjectCtx`, not used directly.
#[derive(Debug)]
pub struct ObjectPermit {
    _inner: CountPermit,
}

// ============================================================================
// Enumeration Batch Configuration
// ============================================================================

/// How many directory entries to process per Enumerate task before re-enqueuing.
///
/// # Tradeoffs
///
/// | Batch Size | Pros | Cons |
/// |------------|------|------|
/// | Small (8-16) | Better responsiveness, interleaves with scans | More task overhead |
/// | Large (64-128) | Less overhead per object | May starve scan tasks |
///
/// # Memory Impact
///
/// Caps the size of `CursorState::FsDir::entries` vector, bounding per-task
/// memory to roughly `ENUM_BATCH_SIZE * sizeof(PathBuf)`.
pub const ENUM_BATCH_SIZE: usize = 32;

/// Maximum FetchSync tasks to spawn per Enumerate execution.
///
/// Even with frontier permits available, we limit spawning to avoid
/// overwhelming the executor's queues in a single task execution.
///
/// # Why This Limit?
///
/// Without this cap, a single Enumerate hitting a directory with 10,000 files
/// could enqueue 10,000 FetchSync tasks in one shot, causing:
/// - Memory spike from task queue growth
/// - Latency spike as other workers wait for queue access
/// - Unfair scheduling (one source dominates)
pub const MAX_FETCH_SPAWNS_PER_ENUM: usize = ENUM_BATCH_SIZE;

// ============================================================================
// Task Metrics
// ============================================================================

/// Per-task-type metrics for observability.
///
/// # Aggregation
///
/// These metrics are typically per-worker and merged after executor shutdown.
/// All counters are monotonically increasing within a worker's lifetime.
///
/// # Interpreting Metrics
///
/// - `enumerate_backpressure > 0`: Frontier is limiting discovery rate (expected behavior)
/// - `bytes_fetched > bytes_scanned`: Overlap bytes or budget enforcement discarding data
/// - `objects_discovered > objects_completed`: Work still in flight or incomplete run
#[derive(Clone, Copy, Debug, Default)]
pub struct TaskMetrics {
    /// Enumerate tasks executed (includes re-enqueued tasks).
    pub enumerate_count: u64,
    /// Objects discovered and handed off to FetchSync.
    pub objects_discovered: u64,
    /// Enumerate tasks re-enqueued due to frontier backpressure.
    /// High values indicate discovery outpacing scan throughput.
    pub enumerate_backpressure: u64,
    /// FetchSync tasks executed (one per chunk read).
    pub fetch_sync_count: u64,
    /// Total bytes read from storage (includes overlap bytes).
    pub bytes_fetched: u64,
    /// Scan tasks executed (one per buffer processed).
    pub scan_count: u64,
    /// Payload bytes scanned (excludes overlap prefix).
    pub bytes_scanned: u64,
    /// Objects where all chunks have been scanned and permit released.
    pub objects_completed: u64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn frontier_try_acquire_does_not_block() {
        let frontier = ObjectFrontier::new(1);

        let p1 = frontier.try_acquire();
        assert!(p1.is_some());

        let p2 = frontier.try_acquire();
        assert!(p2.is_none());

        drop(p1);

        let p3 = frontier.try_acquire();
        assert!(p3.is_some());
    }

    #[test]
    fn object_ctx_releases_permit_on_drop() {
        let frontier = ObjectFrontier::new(1);

        // Create object context
        let desc = ObjectDescriptor {
            path: PathBuf::from("/test"),
            size_hint: 1000,
            object_id: ObjectId {
                source: SourceId(0),
                idx: 0,
            },
            source_id: SourceId(0),
        };

        let ctx = frontier.try_acquire_ctx(desc, FileId(0));
        assert!(ctx.is_some());
        assert_eq!(frontier.in_flight(), 1);

        // Clone the ref (simulating task spawn)
        let ctx2 = ctx.as_ref().map(Arc::clone);
        assert_eq!(frontier.in_flight(), 1); // Still 1

        // Drop first ref
        drop(ctx);
        assert_eq!(frontier.in_flight(), 1); // Still held by ctx2

        // Drop last ref
        drop(ctx2);
        assert_eq!(frontier.in_flight(), 0); // Now released
    }

    #[test]
    fn multi_chunk_object_permit_lifetime() {
        // Simulates: FetchSync -> FetchSync -> Scan -> Scan
        // Permit must stay held until final Scan completes

        let frontier = ObjectFrontier::new(1);

        let desc = ObjectDescriptor {
            path: PathBuf::from("/test"),
            size_hint: 1000,
            object_id: ObjectId {
                source: SourceId(0),
                idx: 0,
            },
            source_id: SourceId(0),
        };

        let obj = frontier.try_acquire_ctx(desc, FileId(0)).unwrap();
        assert_eq!(frontier.in_flight(), 1);

        // Simulate FetchSync spawning next FetchSync + Scan
        let obj_for_fetch2 = Arc::clone(&obj);
        let obj_for_scan1 = Arc::clone(&obj);
        drop(obj); // Original FetchSync completes

        assert_eq!(frontier.in_flight(), 1); // Still held

        // FetchSync2 spawns final Scan
        let obj_for_scan2 = Arc::clone(&obj_for_fetch2);
        drop(obj_for_fetch2); // FetchSync2 completes

        assert_eq!(frontier.in_flight(), 1); // Still held by scans

        // Scan1 completes
        drop(obj_for_scan1);
        assert_eq!(frontier.in_flight(), 1); // Still held by scan2

        // Final scan completes
        drop(obj_for_scan2);
        assert_eq!(frontier.in_flight(), 0); // NOW released
    }

    #[test]
    fn task_size_is_reasonable() {
        // Task should fit in ~2 cache lines
        let size = std::mem::size_of::<Task>();
        assert!(size <= 128, "Task size {} exceeds 128 bytes", size);
        println!("Task size: {} bytes", size);
    }

    #[test]
    fn object_descriptor_size_is_reasonable() {
        let size = std::mem::size_of::<ObjectDescriptor>();
        assert!(
            size <= 64,
            "ObjectDescriptor size {} exceeds 64 bytes",
            size
        );
        println!("ObjectDescriptor size: {} bytes", size);
    }

    #[test]
    fn object_ref_clone_is_cheap() {
        // Verify ObjectRef clone doesn't allocate
        let frontier = ObjectFrontier::new(1);

        let desc = ObjectDescriptor {
            path: PathBuf::from("/test"),
            size_hint: 1000,
            object_id: ObjectId {
                source: SourceId(0),
                idx: 0,
            },
            source_id: SourceId(0),
        };

        let obj = frontier.try_acquire_ctx(desc, FileId(0)).unwrap();

        // Clone many times - this should be just atomic increments
        let refs: Vec<_> = (0..1000).map(|_| Arc::clone(&obj)).collect();

        // Strong count should be 1001
        assert_eq!(Arc::strong_count(&obj), 1001);

        drop(refs);
        assert_eq!(Arc::strong_count(&obj), 1);
    }

    #[test]
    fn concurrent_object_completion() {
        use std::thread;

        let frontier = Arc::new(ObjectFrontier::new(10));
        let completed = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let frontier = Arc::clone(&frontier);
                let completed = Arc::clone(&completed);

                thread::spawn(move || {
                    let desc = ObjectDescriptor {
                        path: PathBuf::from(format!("/test/{}", i)),
                        size_hint: 1000,
                        object_id: ObjectId {
                            source: SourceId(0),
                            idx: i as u32,
                        },
                        source_id: SourceId(0),
                    };

                    if let Some(obj) = frontier.try_acquire_ctx(desc, FileId(i as u32)) {
                        // Simulate some work with clones
                        let _refs: Vec<_> = (0..5).map(|_| Arc::clone(&obj)).collect();

                        // Drop all refs
                        drop(_refs);
                        drop(obj);

                        completed.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(completed.load(Ordering::Relaxed), 10);
        assert_eq!(frontier.in_flight(), 0);
    }
}
