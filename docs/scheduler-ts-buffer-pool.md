# Thread-Safe Fixed-Capacity Buffer Pool

## Module Purpose

The `ts_buffer_pool` module implements a **thread-safe, allocation-free buffer recycling system** for scheduler pipelines. It solves the critical problem of efficient I/O buffer management in high-throughput environments by:

1. **Pre-allocating all buffers upfront** - Eliminates allocation overhead in hot paths
2. **Per-worker local caching** - Reduces contention by giving each worker its own queue
3. **Global fallback queue** - Handles non-worker threads (I/O completions, external callers)
4. **Work-conserving stealing** - Prevents starvation by allowing non-worker threads to steal from idle worker queues
5. **RAII guarantees** - Automatic buffer return via `Drop` trait, preventing leaks

The pool is used by both local and remote scheduler paths. In the current remote pipeline (`crates/scanner-scheduler/src/scheduler/remote.rs`), it is configured with `workers=1` and `local_queue_cap=1`, so behavior is mostly global-queue based.

---

## Design Rationale

### Why Pooling?

Standard allocation (`Vec::with_capacity`, `Box::new`) has unavoidable costs in performance-critical code:

- **System call overhead** - Memory allocator lock contention
- **Cache misses** - New allocations fragment memory
- **Garbage collection pressure** - Freed buffers may be coalesced/defragmented

The remote backend needs to process 64KB chunks at line rates. Pooling amortizes the cost of buffer creation (one-time, at startup) across millions of acquisitions.

### Why Per-Worker Local Queues?

A naive single global queue creates a bottleneck:

```
Global Queue (1)
    ↓
    All 8 workers contend on same lock/CAS
    Millions of operations → severe cache bouncing
```

Per-worker local queues enable **thread-local allocation** when the worker acquires its own buffer:

```
Worker 0 Local     Worker 1 Local     ...  Worker 7 Local
      ↓                  ↓                      ↓
    Fast (no lock)    Fast (no lock)         Fast (no lock)
      ↓                  ↓                      ↓
                   Global Queue (fallback)
                   ↓
                   I/O completions, external calls
```

Performance benefit: **~5-10ns per worker acquire** vs. **~50-100ns on global queue** under contention.

### Why Stealing?

Consider this scenario:

```
Time T=0: Pool initialized, buffers pre-distributed to worker locals
Time T=1: Worker 0 acquires 2 buffers, returns 1
         All 2 of Worker 0's local queue slots filled → can't take more from local

Time T=2: I/O completion handler (non-worker thread) needs a buffer
         Global queue empty (all buffers in worker locals or in-flight)
         Without stealing: STARVATION
         With stealing: Handler scans worker locals, finds available buffer
```

Stealing is **O(workers)** cost but only executed when global is empty (rare in steady state). The guarantee: `try_acquire()` returns `None` only when the pool is **truly exhausted** (all buffers in-flight).

### Why RAII?

Pooled buffers are long-lived objects that can be moved between threads. Manual return is error-prone:

```rust
// Without RAII: easy to leak on early return
fn process_chunk(pool: &TsBufferPool) -> Result<()> {
    let buf = pool.acquire();
    do_work(&buf)?;  // Returns early on error
    pool.release_box(buf);  // Never reached!
}

// With RAII: guaranteed return
fn process_chunk(pool: &TsBufferPool) -> Result<()> {
    let buf = pool.acquire();
    do_work(&buf)?;  // buf dropped here on error, automatically returned
}
```

---

## Allocation Patterns

### Pre-seeding Strategy

On pool creation, buffers are **pre-distributed** from the global queue to worker locals to reduce cold-start contention:

```rust
pub fn new(cfg: TsBufferPoolConfig) -> Self {
    let global = ArrayQueue::new(cfg.total_buffers);

    // 1. Fill global with all buffers
    for _ in 0..cfg.total_buffers {
        let buf = vec![0u8; cfg.buffer_len].into_boxed_slice();
        global.push(buf).expect("...");
    }

    // 2. Seed worker locals from global
    for local in locals.iter() {
        for _ in 0..cfg.local_queue_cap {
            if let Some(buf) = global.pop() {
                local.push(buf).ok();
            }
        }
    }
}
```

**Memory layout after pre-seeding:**
```
Config: 4 workers, 2 local_queue_cap, 12 total_buffers

Before seeding:
  Global: [B0, B1, B2, ..., B11]  (12 buffers)
  Locals: []  []  []  []

After seeding:
  Global: [B8, B9, B10, B11]  (4 remaining)
  Locals: [B0, B1]  [B2, B3]  [B4, B5]  [B6, B7]  (8 distributed)
```

### Acquisition Routing

```
try_acquire() {
    // Fast path (5-10ns on worker thread)
    if on_worker_thread {
        if local_queue.pop() {
            return buffer  ← Fast: no lock, TLS lookup only
        }
    }

    // Fallback (20-50ns, still lock-free via CAS)
    if global_queue.pop() {
        return buffer
    }

    // Steal path (O(workers), only when global empty)
    for each worker_local {
        if worker_local.pop() {
            return buffer
        }
    }

    return None  ← Only when truly exhausted
}
```

Current wiring note: the worker-local fast path requires threads to set
`worker_id` TLS (`set_current_worker_id(Some(id))`). No current scheduler
path calls this, so production routing is typically global pop then steal.

### Release Routing

```
release_box(buf) {
    // Fast path (5-10ns on worker thread)
    if on_worker_thread {
        if local_queue.push(buf) == Ok(()) {
            return  ← Preferred: stays in worker's cache
        }
        // Local queue full, fall through
    }

    // Fallback (20-50ns)
    if global_queue.push(buf) == Ok(()) {
        return  ← Always succeeds within capacity
    }

    panic!("double-release or accounting bug")
}
```

### Capacity Constraints

Configuration trade-offs:

| Configuration | Consequence |
|---------------|-------------|
| `total_buffers < workers * local_queue_cap` | Workers cannot all fill their local caches simultaneously; global becomes bottleneck |
| `total_buffers == workers * local_queue_cap` | Tight sizing; non-worker threads must always steal |
| `total_buffers > workers * local_queue_cap` | Healthy global reserve; non-worker threads rarely steal |

**Recommended sizing:**
- `buffer_len`: Match your I/O chunk size (e.g., 64KB for file scanning)
- `total_buffers`: `workers * local_queue_cap * 1.25` (25% global reserve)
- `local_queue_cap`: 4-8 (small to prevent hoarding)

---

## Thread Safety

### Synchronization Primitives

The pool uses **lock-free queues** (from `crossbeam_queue`) to achieve thread safety without mutex locks:

1. **`ArrayQueue<T>`** - Bounded MPMC queue using compare-and-swap (CAS) atomics
   - No allocation on acquire/release (fixed capacity)
   - Lock-free pops and pushes (or fast backoff)

2. **`CachePadded<T>`** - Wraps each per-worker queue to prevent false sharing
   - Pads to cache line size (128 bytes = 2x64-byte cache lines)
   - Adjacent workers' queue indices never share same cache line
   - Critical for scalability on multi-core systems

### Memory Ordering

```rust
// ArrayQueue uses std::sync::atomic with Acquire/Release ordering
// This ensures:
// 1. No data races on buffer contents
// 2. No reordering of queue operations
// 3. Happens-before relationships between acquire/release

if let Some(buf) = local_queue.pop()  {  // Acquire: ensure subsequent reads see latest state
    // ... use buf safely ...
    // buf dropped here
}
// Drop impl calls release_box
if global_queue.push(buf).is_ok()  {     // Release: flush any writes before returning to pool
    // ...
}
```

### Invariants Maintained

1. **Leak-free**: Every `TsBufferHandle` drop calls `release_box()`, returning buffer to pool
   - `impl Drop for TsBufferHandle`: `self.buf.take()` ensures exactly one return
   - Even if task is cancelled/panicked, `Drop` runs

2. **No double-release**: Global queue overflow panics
   ```rust
   self.inner.global.push(buf)
       .expect("buffer pool overflow: global queue full (double release or accounting bug)");
   ```
   This is **not a performance panic** but an assert for correctness.

3. **Fixed capacity**: Queue inventory plus in-flight handles is constant
   - `available_total() <= total_buffers` at runtime
   - `available_total() == total_buffers` only when no `TsBufferHandle` is in-flight

4. **Work-conserving**: `try_acquire()` returns `None` only when all queues are empty
   - Stealing path guarantees non-worker threads don't starve
   - Liveness is guaranteed by the steal loop (O(workers) scan)

---

## Integration with Remote Backend

The buffer pool is used in remote backend **I/O task execution** to provide buffers for reading network data:

### Task Flow

```
scan_remote(...)
  │
  ├─ Discovery thread
  │   ├─ CountBudget::acquire(1) for object lifecycle
  │   └─ send ObjectWork on bounded channel
  │
  ├─ I/O thread (io_worker_loop)
  │   ├─ buf = acquire_buffer_blocking(pool, stop)
  │   │        (spin/park loop around pool.try_acquire())
  │   ├─ fetch_range(..., &mut buf[..request_len])
  │   └─ cpu.spawn(CpuTask::ScanChunk { buf, ... })
  │
  └─ CPU worker
      ├─ scan chunk
      └─ drop(buf)                    ← Automatic return via TsBufferHandle::Drop
```

### Backpressure Mechanism

Buffer acquisition is **bounded by the pool itself** (not by a separate buffer token budget):

```rust
// remote.rs
let mut buf = match acquire_buffer_blocking(&pool, &stop) {
    Some(b) => b,
    None => return, // stop requested
};
let dst = &mut buf.as_mut_slice()[..request_len];
let fetched = backend.fetch_range(&work.handle, base_offset, dst)?;
cpu.spawn(CpuTask::ScanChunk { buf, ... })?;
```

Remote backpressure chain in current code:
- `CountBudget` bounds discovered-but-not-complete objects.
- Bounded channel (`object_queue_cap`) bounds discovery to I/O queue depth.
- `TsBufferPool` bounds in-flight chunk buffers; I/O threads block in `acquire_buffer_blocking()` when empty.

### Memory Accounting

```
Peak memory = total_buffers * buffer_len

Example:
  - 64 workers, 4 local_queue_cap, 256 total_buffers
  - 64KB buffer size

  Peak = 256 * 64KB = 16MB fixed
  (Does not grow under load, unlike unbounded allocation)
```

---

## Key Types

### `TsBufferPoolConfig`

Configuration struct for pool initialization:

```rust
pub struct TsBufferPoolConfig {
    /// Size of each buffer in bytes
    pub buffer_len: usize,

    /// Total number of buffers in pool
    pub total_buffers: usize,

    /// Number of workers (for per-worker local queues)
    pub workers: usize,

    /// Capacity of each per-worker local queue
    pub local_queue_cap: usize,
}
```

**Key methods:**
- `validate()` - Assert invariants; panics on invalid config
- `peak_memory_bytes()` - Total memory usage (`total_buffers * buffer_len`)
- `total_local_capacity()` - Sum of all local queues (`workers * local_queue_cap`)

**Validation:**
```
✓ buffer_len > 0
✓ total_buffers > 0
✓ workers > 0
✓ local_queue_cap > 0
✓ total_buffers >= workers
⚠ debug warning when `total_buffers < workers * local_queue_cap`
```

### `TsBufferPool`

The main pool handle (cheaply cloneable):

```rust
pub struct TsBufferPool {
    inner: Arc<Inner>,
}
```

**Clone semantics**: `clone()` creates another handle to the **same pool** (no duplication). All handles share the same buffer inventory.

**Key methods:**

| Method | Purpose |
|--------|---------|
| `new(cfg)` | Create pool; allocates all buffers upfront |
| `try_acquire()` → `Option<TsBufferHandle>` | Non-blocking; returns `None` only if exhausted |
| `acquire()` → `TsBufferHandle` | Panics if exhausted (use after backpressure gating) |
| `buffer_len()` | Query buffer size |
| `workers()` | Query worker count |

**Example usage:**
```rust
let cfg = TsBufferPoolConfig {
    buffer_len: 64 * 1024,
    total_buffers: 256,
    workers: 8,
    local_queue_cap: 4,
};
let pool = TsBufferPool::new(cfg);

// In worker thread (fast path):
let mut buf = pool.acquire();
buf.as_mut_slice()[0..100].copy_from_slice(&data);
// buf automatically returned on drop
```

### `TsBufferHandle`

RAII wrapper around a pooled buffer:

```rust
pub struct TsBufferHandle {
    pool: TsBufferPool,
    buf: Option<Box<[u8]>>,
}
```

**Key properties:**
- **Size**: 24 bytes (Arc ptr + Option)
- **Ownership**: Exclusive (no `Clone` to prevent double-free)
- **Lifetime**: Buffer is returned to pool on `Drop`

**Key methods:**

| Method | Purpose |
|--------|---------|
| `as_slice(&self) → &[u8]` | View full buffer (not just filled bytes) |
| `as_mut_slice(&mut self) → &mut [u8]` | Mutable access |
| `len() → usize` | Buffer size |
| `clear(&mut self)` | Zero-fill (for sensitive data) |
| `ptr_usize() → usize` | Buffer address as int (debugging) |

**Important caveat:**

> `as_slice()` returns the **entire buffer**, not just filled bytes. For scan tasks that partially fill buffers, use `TsChunk` (in scheduler module) which tracks filled length via `len` and `buf_offset` fields.

**Example with partial fill:**
```rust
let mut buf = pool.acquire();
let n = read_socket(&mut buf.as_mut_slice()[..1024])?;
// buf.as_slice().len() == 64KB (full buffer)
// But only first 1024 bytes are valid!

// Better: use TsChunk which tracks this
let chunk = TsChunk::new(
    obj_id,     // object identifier
    0,          // base_offset
    n as u32,   // len (filled length)
    0,          // prefix_len (no overlap for first chunk)
    0,          // buf_offset
    buf,
);
```

### `Inner` (Internal)

Shared state behind `Arc`:

```rust
struct Inner {
    buffer_len: usize,
    global: ArrayQueue<Box<[u8]>>,
    locals: Vec<CachePadded<ArrayQueue<Box<[u8]>>>>,
}
```

**Memory layout:**
- `buffer_len`: 8 bytes (constant)
- `global`: ~32 bytes + array storage (all buffers in worst case)
- `locals`: ~24 bytes + `workers * 128 bytes` (CachePadded queues)

Each `CachePadded<ArrayQueue>` is **128 bytes** (two 64-byte cache lines) to prevent false sharing between adjacent workers' queue indices.

---

## Performance Characteristics

### Lock-Free Design

Both acquisition and release use **CAS-based atomics** (no mutex locks):

```
Benchmark (single-threaded, 1M operations):
  acquire() + drop():  ~12ns per round-trip
  (Compare: malloc/free: ~50-100ns per round-trip)
```

### Scaling with Contention

| Scenario | Path | Latency |
|----------|------|---------|
| Worker thread, local hit | Local pop (TLS) | ~5-10ns |
| Worker thread, local miss | Global pop (CAS) | ~20-50ns |
| Non-worker thread | Global pop (CAS) | ~20-50ns |
| All queues empty | Steal scan (O(workers)) | ~100-500ns |

### False Sharing Prevention

Without `CachePadded`:
```
Cache line 0                          Cache line 1
[Worker0_q_idx][Worker1_q_idx] | [Worker2_q_idx][Worker3_q_idx]

Worker 0 updates index → Invalidates Worker 1's cache
Worker 1 updates index → Invalidates Worker 0's cache
Result: Severe cache line bouncing, ~10x latency increase
```

With `CachePadded` (128 bytes = 2 cache lines per queue):
```
Worker 0 local queue occupies cache lines 0-1
Worker 1 local queue occupies cache lines 2-3
...
No sharing between workers → Independent cache lines
Result: Scales linearly with workers
```

---

## Alignment Note (Buffer Allocation)

This implementation uses `Box<[u8]>` which provides **no alignment guarantee** beyond 1 byte (required for `u8`).

### Sufficient For
- Regular `read()` syscalls (no alignment requirement)
- Buffered I/O (any alignment accepted)
- Network sockets (no alignment requirement)

### NOT Sufficient For
- **O_DIRECT** - Requires 512 or 4096 byte alignment (varies by filesystem)
- **io_uring registered buffers** - Requires page alignment (4096+ bytes)
- **DMA operations** - May require memory address alignment

### Future Enhancement (Option B)

To support O_DIRECT or other alignment-requiring I/O, consider:

```rust
// Feature-gated: buffer alignment support
#[cfg(feature = "aligned_buffers")]
fn aligned_buffer(len: usize, align: usize) -> Box<[u8]> {
    let layout = Layout::from_size_align(len, align).unwrap();
    unsafe {
        let ptr = alloc::alloc::alloc(layout) as *mut [u8];
        Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len))
    }
}
```

Current implementation prioritizes simplicity and compatibility; alignment can be added if remote backend requires O_DIRECT in future.

---

## Testing & Validation

The module includes comprehensive tests validating:

1. **Configuration validation** - Panics on invalid configs
2. **Pre-seeding** - Buffers correctly distributed to worker locals
3. **Acquire/release cycles** - RAII drop returns buffers
4. **Buffer reuse** - Unique buffer addresses ≤ pool capacity
5. **Stealing** - Non-worker threads acquire when global empty
6. **Concurrent stress** - 8 threads, 10K ops each, verification of reuse
7. **Executor integration** - Real-world usage with 50K scan tasks

Example test:
```rust
#[test]
fn stealing_prevents_starvation() {
    // All buffers in worker locals, none in global
    let pool = TsBufferPool::new(cfg);
    assert_eq!(pool.available_global(), 0);

    // Non-worker thread (no TLS worker_id) acquires via stealing
    assert!(pool.try_acquire().is_some());

    // One buffer already acquired above; 7 remain
    for _ in 1..8 {
        assert!(pool.try_acquire().is_some());
    }
}
```

---

## Summary

The `TsBufferPool` module provides a **high-performance, thread-safe buffer recycling system** used across scheduler paths. Its key properties:

- **Zero-allocation hot path** - All buffers pre-allocated; acquire/release are lock-free CAS operations
- **Per-worker local caching** - Active when caller threads set `worker_id` TLS
- **Work-conserving stealing** - Prevents starvation of non-worker threads
- **Memory-bounded** - Fixed peak memory usage, controlled by configuration
- **Leak-free RAII** - Automatic buffer return on `Drop`, no manual tracking
- **Correct** - Invariants maintained: no leaks, no double-release, no starvation

In the current remote backend wiring (`workers=1`, `local_queue_cap=1`), the pool primarily acts as a bounded global lifecycle tracker, while preserving the same leak-free/work-conserving guarantees.
