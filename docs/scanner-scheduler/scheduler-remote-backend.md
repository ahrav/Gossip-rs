# Remote Fetch Backend Module

**Location:** `crates/scanner-scheduler/src/scheduler/remote.rs`

**Purpose:** HTTP/object-store backend abstraction for the scheduler's remote scanning pipeline. Handles concurrent fetching, retry logic, and backpressure control.

---

## 1. Module Purpose

The remote backend module provides a complete scanning pipeline for remote data sources (S3, HTTP, GCS, etc.). It abstracts network I/O behind a trait-based interface, leaving the scheduler to handle:

- Thread management (separate I/O and CPU pools)
- Retry policies with exponential backoff
- Backpressure via bounded queues and budget constraints
- Buffer pooling and lifecycle management
- Finding deduplication and structured event emission

**Key insight:** Network latency and CPU scanning are naturally decoupled: I/O threads fetch while CPU workers scan independently.

---

## 2. Architecture

### High-Level Pipeline

```
Discovery Thread       I/O Threads (N)           CPU Workers (M)
┌──────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐
│ list_page()      │  │ ObjectWork recv      │  │ ScanChunk task      │
│ ↓                │  │ ↓                    │  │ ↓                   │
│ bounded chan ←──────→ fetch_range()        │  │ scan_chunk_into()   │
│ (discovery →     │  │ retry/backoff        │  │ emit findings       │
│  I/O backpressure│  │ ↓                    │  │ release buffer      │
│                  │  │ ScanChunk task ─────────→ (via TsBufferPool)   │
│ ObjectToken      │  │ (buffer handoff)     │  │                     │
│ (permit for      │  │                      │  │                     │
│  in-flight limit)│  │                      │  │                     │
└──────────────────┘  └──────────────────────┘  └─────────────────────┘
```

### Backpressure Chain

```
Discovery ──→ object_queue_cap ──→ I/O threads ──→ pool_buffers ──→ CPU executor
         │                                    │
    CountBudget                        TsBufferPool
    (max_in_flight_objects)            (buffer lifecycle)
```

Three layers of backpressure:

1. **CountBudget (`max_in_flight_objects`):** Limits discovered-but-not-complete objects. When full, discovery blocks until a chunk task completes and releases its permit.

2. **Bounded Channel (`object_queue_cap`):** Queue from discovery to I/O threads. When full, discovery blocks (with timeout loop to allow graceful shutdown).

3. **Buffer Pool (`pool_buffers`):** Total buffers across I/O and CPU threads. I/O threads acquire just-in-time, CPU workers release after scanning. No buffers held during backoff sleep.

### Key Design Decisions

| Decision                         | Rationale                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Separate I/O and CPU threads** | Network latency doesn't block scanning. I/O can queue work while CPU workers are busy.                       |
| **GlobalOnly buffer pool**       | I/O threads acquire, CPU workers release. Simplifies coordination—no per-thread caching.                     |
| **ObjectToken via Arc**          | Each object's in-flight permit lives until all its chunks complete. Automatic release on last chunk done.    |
| **Bounded object queue**         | Provides discovery backpressure without additional mechanisms.                                               |
| **Dedupe within chunk only**     | Cross-chunk deduplication would require global state. Per-chunk dedup prevents most redundancy from overlap. |

---

## 3. Retry Policies

### ErrorClass

Errors are classified into two categories:

```rust
pub enum ErrorClass {
    /// Transient error - worth retrying
    /// Examples: timeout, 503 Service Unavailable, rate limit
    Retryable,

    /// Permanent error - don't retry
    /// Examples: 404 Not Found, auth failure, invalid response format
    Permanent,
}
```

Backends implement `classify_error(&self, err: &Self::Error) -> ErrorClass` to map their error types.

### RetryPolicy

```rust
pub struct RetryPolicy {
    pub max_attempts: u32,      // e.g., 4 (initial + 3 retries)
    pub base_delay: Duration,   // e.g., 50ms
    pub max_delay: Duration,    // e.g., 2s
    pub jitter_pct: u32,        // e.g., 20 (±20% of computed delay)
}
```

**Default:** `4 attempts, 50ms base, 2s cap, 20% jitter`

### Backoff Computation

For attempt N (1-indexed):

1. **Exponential growth:** `delay = base_delay * 2^(N-1)`, capped at `max_delay`
2. **Jitter:** Add uniform random offset in `[-jitter_ns, +jitter_ns]`
3. **Result:** Uniform random in `[delay - jitter, delay + jitter]`

**Why jitter?** Prevents thundering herd when multiple objects fail simultaneously. Spreads retry attempts across time.

### Per-Object Time Budget

```rust
pub max_object_time: Option<Duration>,  // e.g., 30 seconds
```

Each object has a total time limit (including all retries). If a backoff would exceed the budget, the object fails immediately rather than sleeping.

### Error Handling in I/O Worker

```
For each chunk:
  For each attempt:
    Try fetch_range()
    ✓ Success → enqueue ScanChunk task, advance offset
    ✗ Error:
      Match classify_error():
        Permanent → fail object (no more retries)
        Retryable:
          if attempts < max_attempts:
            compute_backoff()
            check time_budget (if set)
            sleep(backoff)
            retry (re-acquire buffer)
          else:
            fail object (exhausted retries)
```

Key: **Buffers are dropped before sleeping** to avoid starving other workers.

---

## 4. Transport Abstraction

### RemoteBackend Trait

```rust
pub trait RemoteBackend: Send + Sync + 'static {
    type Object: Send + 'static;      // Handle (S3 key, HTTP URL, etc.)
    type Cursor: Default + Send + 'static;      // Pagination state
    type Error: Debug + Send + Sync + 'static;  // Error type

    /// List up to `max` objects starting from cursor.
    /// Returns empty when enumeration is complete, updates cursor for next page.
    fn list_page(&self, cursor: &mut Self::Cursor, max: usize)
        -> Result<Vec<RemoteObject<Self::Object>>, Self::Error>;

    /// Fetch exactly `dst.len()` bytes from object at `start`.
    /// CONTRACT (CRITICAL):
    /// - If start + dst.len() <= object_size: MUST return dst.len()
    /// - If start >= object_size: MUST return 0
    /// - If start < size < start + dst.len(): MUST return (size - start)
    /// Partial reads within valid range are NOT allowed.
    fn fetch_range(&self, obj: &Self::Object, start: u64, dst: &mut [u8])
        -> Result<usize, Self::Error>;

    /// Classify error for retry decisions.
    fn classify_error(&self, err: &Self::Error) -> ErrorClass;
}
```

### fetch_range Contract

This is the critical contract. **Backends must not return partial reads in the middle of a valid range:**

```
VALID RESPONSES:
  start=0, obj_size=100, request=50
    → Must return exactly 50 bytes

  start=90, obj_size=100, request=50 (partial)
    → Must return 10 bytes (size - start)

  start=100, obj_size=100, request=50 (EOF)
    → Must return 0 bytes

INVALID:
  start=0, obj_size=100, request=50
    → Returns 25 bytes (mid-request failure)
    → Must return error instead!
```

**Why strict contract?** Simplifies scheduler—it doesn't need retry loops for partial reads. S3/HTTP/GCS backends loop internally:

```rust
// Example S3 implementation
fn fetch_range(&self, obj: &Key, start: u64, dst: &mut [u8]) -> Result<usize, Error> {
    let mut filled = 0;
    while filled < dst.len() {
        match self.s3_read(obj, start + filled as u64, &mut dst[filled..])? {
            0 => break,  // EOF
            n => filled += n,
        }
    }
    Ok(filled)
}
```

### RemoteObject Wrapper

```rust
pub struct RemoteObject<H> {
    pub handle: H,              // Backend-specific (S3 key, URL, etc.)
    pub size: u64,              // Object size in bytes
    pub display: Vec<u8>,       // Path/key for output (can be non-UTF8)
}
```

---

## 5. Integration with Scheduler

### Configuration

```rust
pub struct RemoteConfig {
    pub cpu_workers: usize,             // e.g., 8
    pub io_threads: usize,              // e.g., 8
    pub chunk_size: usize,              // e.g., 256KB
    pub max_in_flight_objects: usize,   // e.g., 512
    pub object_queue_cap: usize,        // e.g., 256
    pub discover_batch: usize,          // e.g., 256 objects per list_page
    pub pool_buffers: usize,            // e.g., 64
    pub retry: RetryPolicy,             // Exponential backoff config
    pub max_object_time: Option<Duration>, // e.g., 30 seconds
    pub seed: u64,                      // PRNG seed
    pub dedupe_within_chunk: bool,      // Per-chunk dedup
}
```

### Statistics & Reporting

```rust
pub struct RemoteRunReport {
    pub remote: RemoteStats {
        objects_discovered: u64,
        objects_enqueued: u64,
    },
    pub io: IoStats {
        objects_started: u64,
        objects_completed: u64,
        objects_failed: u64,
        chunks_fetched: u64,
        payload_bytes_fetched: u64,  // Excludes overlap
        retryable_errors: u64,
        permanent_errors: u64,
        retries: u64,
    },
}
```

### Entry Point

```rust
pub fn scan_remote<B: RemoteBackend>(
    engine: Arc<MockEngine>,
    backend: Arc<B>,
    cfg: RemoteConfig,
    event_sink: Arc<dyn EventOutput>,
) -> Result<(RemoteRunReport, MetricsSnapshot), RemoteRunError<B::Error>>
```

**Execution flow:**

1. Validate config (thread counts, buffer sizes, chunk constraints)
2. Create buffer pool, budget, CPU executor
3. Spawn I/O threads (listen on bounded channel)
4. Run discovery loop:
   - Enumerate objects via `list_page()`
   - Acquire in-flight permit
   - Send `ObjectWork` to I/O threads
5. Wait for I/O threads to drain
6. Join CPU executor
7. Flush event sink and return report + metrics

---

## 6. Key Types and Functions

### Internal Types

| Type            | Purpose                                                                                   |
| --------------- | ----------------------------------------------------------------------------------------- |
| `ObjectToken`   | Holds in-flight permit and file metadata. Released when last Arc drops (all chunks done). |
| `ObjectWork<H>` | Sent from discovery to I/O threads. Contains object handle, size, and token.              |
| `CpuTask`       | Task sent to CPU executor. Wraps buffer, offset, and findings info.                       |
| `CpuScratch`    | Per-worker state: engine, event sink, scanning scratch space.                             |

### Public Functions

#### Configuration Validation

```rust
impl RemoteConfig {
    pub fn validate(&self, engine: &MockEngine) {
        // Checks:
        // - All thread counts > 0
        // - retry.max_attempts > 0 and retry.jitter_pct <= 100
        // - chunk_size + overlap <= BUFFER_LEN_MAX
    }
}
```

#### Retry Computation

```rust
fn compute_backoff(attempt: u32, policy: RetryPolicy, rng: &mut XorShift64) -> Duration {
    // Exponential delay with jitter
    // Returns Duration in [delay - jitter, delay + jitter]
}
```

#### Buffer Acquisition

```rust
fn acquire_buffer_blocking(pool: &TsBufferPool, stop: &AtomicBool) -> Option<TsBufferHandle> {
    // Spin-then-park: 200 spins (~200ns), then 200µs park timeout
    // Returns None if stop flag is set
}
```

#### I/O Worker Loop

```rust
fn io_worker_loop<B: RemoteBackend>(
    wid: usize,
    backend: Arc<B>,
    rx: chan::Receiver<ObjectWork<B::Object>>,
    pool: TsBufferPool,
    cpu: ExecutorHandle<CpuTask>,
    cfg: RemoteConfig,
    overlap: usize,
    stop: Arc<AtomicBool>,
) -> IoStats {
    // Core worker:
    // 1. Receive object from discovery
    // 2. For each chunk (with overlap):
    //   a. Calculate range [base_offset, base_offset + prefix_len + payload_len)
    //   b. Retry loop: acquire buffer, fetch_range, backoff on error
    //   c. Enqueue ScanChunk task
    // 3. Return stats
}
```

**Key behaviors:**
- Buffers acquired just-in-time (inside retry loop)
- Buffers dropped before backoff sleep
- Retryable errors trigger backoff + retry
- Permanent errors fail object immediately
- Time budget checked before each chunk and before backoff

#### CPU Worker & Finding Emission

```rust
fn cpu_runner(task: CpuTask, ctx: &mut WorkerCtx<CpuTask, CpuScratch>) {
    // 1. Scan chunk: engine.scan_chunk_into()
    // 2. Record pending finding counts before/after prefix drop
    // 3. If dedupe_within_chunk:
    //    a. Drain via EngineScratch trait into FindingWithHash carriers
    //    b. apply_cross_rule_dedupe() using (root_hint, optional span, norm_hash)
    //    c. emit_findings() via shared local_fs_owner helper
    // 4. Else drain raw findings and emit via the same shared helper
    // 5. account_effective_dropped_findings() for scheduler-side pruning
    // 6. Return buffer to pool (on drop)
}
```

Remote now reuses the same within-chunk cross-rule dedupe path as local FS
backends by calling `local_fs_owner::apply_cross_rule_dedupe` and
`local_fs_owner::emit_findings`. The mock engine's trait-based drain provides
`FindingWithHash<FindingRec>` carriers with deterministic zero hashes, which
preserves shared dedupe semantics in tests without introducing backend-specific
dedupe logic.

---

## 7. Error Handling & Edge Cases

### Partial Read Contract Violation

If a backend returns fewer bytes than requested without reaching EOF (e.g., network timeout mid-read), the scheduler treats this as a **permanent error** and fails the object:

```rust
if fetched < request_len {
    let end_offset = base_offset + fetched as u64;
    if end_offset != size {
        // Partial read that doesn't reach EOF = contract violation
        stats.permanent_errors += 1;
        failed = true;
        break 'chunk_loop;
    }
}
```

### Timeout Handling

Discovery uses a timeout loop to prevent deadlock:

```rust
loop {
    if stop.load(Ordering::Relaxed) {
        break 'discovery;
    }
    match tx.send_timeout(work, Duration::from_millis(100)) {
        Ok(()) => break,
        Err(Timeout(work)) => continue,  // Retry
        Err(Disconnected(_)) => break 'discovery,  // I/O threads exited
    }
}
```

### Graceful Shutdown

Stop flag is checked:
- Before each chunk fetch
- Before acquiring buffer
- Before each discovery iteration
- Before each send

When set, workers stop quickly; any already-enqueued CPU scan tasks may still finish.

---

## 8. Testing

### Test Fixtures

1. **MockBackend:** Simple in-memory backend for basic functionality
2. **RetryBackend:** Fails N times then succeeds (retry testing)
3. **PartialReadBackend:** Returns limited bytes per read (contract violation detection)
4. **PermanentErrorBackend:** Always fails (error classification)

### Key Test Cases

| Test                                               | Coverage                     |
| -------------------------------------------------- | ---------------------------- |
| `remote_pipeline_finds_secret`                     | Basic end-to-end scanning    |
| `remote_pipeline_handles_boundary_spanning_secret` | Overlap handling             |
| `remote_pipeline_handles_empty_backend`            | Edge case: no objects        |
| `remote_pipeline_processes_multiple_objects`       | Parallelism, multiple files  |
| `remote_pipeline_retries_transient_failures`       | Retry logic with backoff     |
| `backoff_respects_max_delay`                       | Exponential cap at max_delay |
| `backoff_applies_jitter`                           | Jitter within expected range |
| `config_validation_rejects_invalid`                | Buffer size constraints      |
| `partial_reads_cause_object_failure`               | Contract violation detection |
| `permanent_errors_cause_immediate_failure`         | No-retry classification      |
| `retryable_errors_exhaust_attempts`                | Retry exhaustion             |

---

## 9. Performance Characteristics

### Throughput Optimization

1. **Buffer pooling:** Avoids allocation/deallocation overhead
2. **Separate I/O threads:** Network latency hidden behind queue
3. **Chunking with overlap:** Pattern spans across boundaries
4. **Per-chunk dedup:** Reduces finding output without global state
5. **Spin-then-park:** Low-latency buffer acquisition for typical case

### Memory Usage

- **Buffer pool:** `pool_buffers * (overlap + chunk_size)` bytes
- **In-flight objects:** `max_in_flight_objects * metadata_size` (~100 bytes per object)
- **Queued work:** `object_queue_cap * work_struct_size` (~200 bytes per work item)

### Concurrency Model

- **Discovery:** 1 thread (enumeration is typically I/O bound)
- **I/O:** N threads (default 8, tunable per workload)
- **CPU:** M threads (default 8, should match CPU cores)
- **No locking:** Only lock-free channels and atomics

---

## 10. Design Tradeoffs

### Why Not Async?

Blocking calls on dedicated I/O threads is simpler than async for moderate concurrency (10-100 threads). For 1000+ concurrent fetches, consider async with tokio.

### Why Spin-Then-Park for Buffer Acquisition?

- **Typical case:** Buffers available immediately (CPU workers release fast)
- **Simple:** No additional synchronization primitives
- **Responsive:** Park timeout allows reaction to stop flag

### Why Dedupe Only Within Chunks?

- Cross-chunk dedup requires global findings collector
- Per-chunk dedup catches most redundancy from overlap
- Simpler, lock-free implementation

### Why Per-Thread CPU Scratch Instead of Global?

- No synchronization overhead
- Cache locality (thread-local data)
- Scales linearly with worker count

---

## 11. Example: Custom S3 Backend

```rust
use scanner_rs::scheduler::remote::{ErrorClass, RemoteBackend, RemoteObject};

pub struct S3Backend {
    client: S3Client,
    bucket: String,
}

impl RemoteBackend for S3Backend {
    type Object = String;  // S3 key
    type Cursor = Option<String>;  // Continuation token
    type Error = S3Error;

    fn list_page(&self, cursor: &mut Option<String>, max: usize)
        -> Result<Vec<RemoteObject<Self::Object>>, Self::Error>
    {
        let resp = self.client.list_objects_v2()
            .bucket(&self.bucket)
            .max_keys(max as u32)
            .continuation_token(cursor.take())
            .send()?;

        let objs = resp.contents().unwrap_or_default()
            .iter()
            .map(|obj| RemoteObject {
                handle: obj.key().unwrap().to_string(),
                size: obj.size().unwrap_or(0) as u64,
                display: obj.key().unwrap().as_bytes().to_vec(),
            })
            .collect();

        *cursor = resp.continuation_token().map(|s| s.to_string());
        Ok(objs)
    }

    fn fetch_range(&self, key: &Self::Object, start: u64, dst: &mut [u8])
        -> Result<usize, Self::Error>
    {
        let mut filled = 0;
        while filled < dst.len() {
            match self.client.get_object()
                .bucket(&self.bucket)
                .key(key)
                .range(format!("bytes={}-{}", start + filled as u64, start + dst.len() as u64 - 1))
                .send()
                .map(|r| r.body.read(&mut dst[filled..]))
            {
                Ok(Ok(0)) => break,  // EOF
                Ok(Ok(n)) => filled += n,
                Ok(Err(e)) => return Err(e.into()),
                Err(e) if e.is_transient() => return Err(e),
                Err(e) => return Err(e),
            }
        }
        Ok(filled)
    }

    fn classify_error(&self, err: &Self::Error) -> ErrorClass {
        match err.kind() {
            S3ErrorKind::ServiceUnavailable | S3ErrorKind::RequestTimeout => {
                ErrorClass::Retryable
            }
            S3ErrorKind::NoSuchKey | S3ErrorKind::AccessDenied => {
                ErrorClass::Permanent
            }
            _ => ErrorClass::Permanent,
        }
    }
}
```

---

## Summary

The remote backend module provides a robust, efficient scanning pipeline for remote data sources. Its key strengths:

1. **Clean abstraction:** `RemoteBackend` trait with strict contracts
2. **Parallel I/O + CPU:** Decoupled network and scanning threads
3. **Smart backpressure:** Three-layer buffering and budget control
4. **Resilient retry:** Exponential backoff with jitter, error classification
5. **Memory efficient:** Buffer pooling, no per-thread caching
6. **Observable:** Detailed statistics and error classification

Use it for S3, HTTP, GCS, or any remote data source with predictable list/fetch APIs.
