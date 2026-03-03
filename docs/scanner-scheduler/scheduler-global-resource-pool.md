# Global Resource Pool Module

## Overview

The `GlobalResourcePool` module provides centralized resource management for "fat" jobs in the scheduler: operations that require significant memory allocations beyond per-object tracking. This includes Git repository scanning, archive extraction, and multi-file container operations.

Current status: this module is implemented and tested in `crates/scanner-scheduler/src/scheduler/global_resource_pool.rs`, but there are no non-test call sites in the scheduler yet.

## 1. Module Purpose

### What It Does

The Global Resource Pool enforces system-wide memory limits on concurrent "fat" jobs by maintaining shared budgets for:

- **Scan Ring Memory**: Fixed-size buffers used during repository/archive traversal (10-50 MB typical per job)
- **Delta Cache Memory**: Decompression and delta resolution caches (25-100 MB typical per job)
- **Spill Slots**: Concurrent disk-spilling operations (limited or unlimited based on configuration)

### Example Use Cases

1. **Git Repository Scanning**: Requires scan ring for commit graph traversal + delta cache for pack file resolution
2. **Archive Extraction**: Requires scan ring for decompression buffers + spill slots if temp files needed
3. **Multi-File Container Scanning**: ZIP/TAR operations with multiple concurrent file extractions

### RAII Guarantee

Resources are managed via `FatJobPermit`—an RAII guard that automatically releases all held resources when dropped, ensuring no leaks even during job cancellation or error paths.

---

## 2. Why Centralized Management Is Needed

### The Problem

Per-object budgets (`ObjectFrontier`) track memory used per individual object, but don't prevent pathological scenarios:

```
Scenario: N concurrent repo jobs with B+D bytes each

Per-object limit: 500 MB per repo
Global available: 1 GB

Without global pool:
  - Job 1 acquires 500 MB (limit met for this object)
  - Job 2 acquires 500 MB (different object, limit met separately)
  - Job 3 acquires 500 MB (different object, limit met separately)

Result: 1.5 GB allocated, but only 1 GB system memory available!
```

### The Solution

The Global Resource Pool enforces a hard cap at the scheduler level:

```
Global Pool Configuration:
  scan_ring_total = 200 MB (shared across ALL jobs)
  delta_cache_total = 400 MB (shared across ALL jobs)

Concurrent Jobs:
  - Job 1: acquires 50 MB scan ring + 100 MB delta → permitted
  - Job 2: acquires 50 MB scan ring + 100 MB delta → permitted
  - Job 3: acquires 50 MB scan ring + 100 MB delta → permitted
  - Job 4: tries 50 MB scan ring → denied (only 50 MB remaining)
           → re-enqueued by scheduler
```

### Key Invariants Maintained

1. **All-or-Nothing Acquisition**: Partial permits are impossible; if any resource is unavailable, the entire request fails and previous acquisitions are rolled back
2. **No Deadlock**: Consistent acquisition order (scan ring → delta cache → spill slot) prevents circular waits
3. **Leak-Free**: Drop implementation releases all resources RAII-style
4. **Bounded Total**: `sum(all active permits' bytes) ≤ configured limits`

---

## 3. SLAs per Job Type

### Job Type: Git Repository Scan

| Aspect           | Value          | Notes                                                 |
| ---------------- | -------------- | ----------------------------------------------------- |
| Scan Ring        | 10-50 MB       | Depends on commit graph depth and complexity          |
| Delta Cache      | 25-100 MB      | Pack file resolution; larger repos need more          |
| Spill Permission | Usually `true` | Candidate buffer may exceed memory, spill to disk     |
| Fairness         | Best effort    | No priority queue; backoff recommended for large jobs |

**Configuration Example**:
```rust
let config = GlobalResourcePoolConfig {
    scan_ring_bytes: 200_000_000,       // 200 MB for ~4 concurrent repos
    delta_cache_bytes: 400_000_000,     // 400 MB for complex packs
    spill_slots: Some(8),               // 8 concurrent spill ops
};
```

### Job Type: Archive Extraction

| Aspect           | Value          | Notes                                |
| ---------------- | -------------- | ------------------------------------ |
| Scan Ring        | File size      | Size of largest file in archive      |
| Delta Cache      | 0              | No delta resolution needed           |
| Spill Permission | Depends on job | Only if extraction may exceed memory |

**Zip note:** current ZIP scanning is file-backed random access and reuses
per-worker buffers; it does not yet acquire a fat-job permit unless spill
materialization is introduced for nested archives.

**Configuration Example**:
```rust
// For archive processing
let request = FatJobRequest::archive(
    10 * 1024 * 1024,  // 10 MB max file size
    true               // May spill to disk
);
```

### Job Type: Multi-File Container

| Aspect           | Value             | Notes                             |
| ---------------- | ----------------- | --------------------------------- |
| Scan Ring        | Largest file size | Or sum if simultaneous extraction |
| Delta Cache      | 0                 | Typically none for containers     |
| Spill Permission | `true`            | Temp files for decompression      |

### Absence of Explicit Priorities

The module does **not** implement job type prioritization. Instead:

- All job types compete fairly for the shared pool
- **Scheduler-level backoff** should handle fairness (e.g., retry large jobs with exponential backoff if they keep failing)
- This keeps the resource pool simple and prevents priority inversion bugs

---

## 4. Permit Management

### Acquisition Semantics

#### All-or-Nothing Guarantee

```rust
let permit = pool.try_acquire_fat_job_permit(
    FatJobRequest {
        scan_ring_bytes: 50_000_000,
        delta_cache_bytes: 100_000_000,
        needs_spill_slot: true,
    }
);

match permit {
    Some(p) => {
        // ALL resources acquired: 50MB scan ring, 100MB delta, 1 spill slot
        // Ready to proceed with job
    }
    None => {
        // NOTHING acquired; pool state unchanged
        // Re-enqueue and retry later
    }
}
```

#### Acquisition Order

Resources are acquired in a fixed sequence to prevent deadlock:

1. **Scan ring bytes** - acquired first
2. **Delta cache bytes** - acquired second (if fails, scan ring is released)
3. **Spill slot** - acquired third (if fails, both byte budgets are released)

This ordering ensures that if step N fails, steps 1 through N-1 are automatically rolled back.

### Release Semantics

#### Automatic via Drop

```rust
impl Drop for FatJobPermit {
    fn drop(&mut self) {
        // Release scan ring bytes
        self.pool.release_scan_ring(self.scan_ring_bytes);

        // Release delta cache bytes
        self.pool.release_delta_cache(self.delta_cache_bytes);

        // Spill slot released automatically by CountPermit Drop
    }
}
```

#### Typical Pattern

```rust
struct GitRepoJob {
    permit: FatJobPermit,  // Held for entire job lifetime
    repo_path: PathBuf,
    // ... other state ...
}

impl GitRepoJob {
    fn execute(&mut self) -> Result<()> {
        // Use permit to constrain resource usage
        let allow_spill = self.permit.can_spill();
        scan_repository(&self.repo_path, allow_spill)?;

        // On return or error, permit is automatically dropped
        Ok(())
    }
}
```

#### Cancel Safety

Jobs cancelled mid-execution simply drop their permit:

```rust
async fn run_job(job: GitRepoJob) {
    // If cancelled here, permit is dropped automatically
    // No manual cleanup needed
    job.execute().await
}
```

### Spill Permission Model

The spill permission uses an enum to distinguish three cases:

```rust
enum SpillGrant {
    NotRequested,           // Job didn't request spill
    Unlimited,              // Spill enabled; no slot counting
    Limited(CountPermit),   // Spill enabled; using 1 counted slot
}
```

**Usage**:
```rust
permit.can_spill()        // true if Unlimited or Limited
permit.spill_is_limited() // true only if Limited
```

**Scenarios**:

| Config                 | Request                   | Result         | Semantics                  |
| ---------------------- | ------------------------- | -------------- | -------------------------- |
| `spill_slots: Some(4)` | `needs_spill_slot: true`  | `Limited`      | Must acquire 1 of 4 slots  |
| `spill_slots: Some(4)` | `needs_spill_slot: false` | `NotRequested` | Spill disallowed           |
| `spill_slots: None`    | `needs_spill_slot: true`  | `Unlimited`    | Spill allowed; no counting |
| `spill_slots: None`    | `needs_spill_slot: false` | `NotRequested` | Spill disallowed           |

---

## 5. Integration Pattern with Scheduler

### Intended Scheduler Workflow

```
┌─────────────────────────────────────────┐
│ Scheduler Main Loop                     │
│                                         │
│ 1. Dequeue job from work queue          │
│ 2. Determine job type & resource needs  │
│ 3. Try acquire global permit            │
└────────────────┬────────────────────────┘
                 │
        ┌────────▼──────────────┐
        │ Permit acquired?      │
        └─────┬────────┬────────┘
         Yes  │        │  No
             │        │
    ┌────────▼──┐  ┌──▼────────────────┐
    │ Start job │  │ Enqueue backoff   │
    │ Hold      │  │ Re-try later with │
    │ permit    │  │ exponential delay │
    └─────┬─────┘  └──────────────────┘
          │
          │ Job executes
          │ (may hit ObjectFrontier limits too)
          │
    ┌─────▼──────────────────┐
    │ Job completes/error    │
    │ Permit dropped →       │
    │ Auto-release resources │
    └────────────────────────┘
```

### Backpressure Strategy

When wired into a scheduler path, the module provides **negative feedback** to the scheduler:

1. **Job Acquisition Fails** → `try_acquire_fat_job_permit()` returns `None`
2. **Scheduler Response** → Re-enqueue job with backoff delay
3. **Why Backoff?** → Prevents busy-spinning; allows other jobs to release resources

```rust
// Pseudocode: scheduler's dequeue loop
loop {
    let job = queue.pop()?;

    loop {
        // Attempt acquisition
        match pool.try_acquire_fat_job_permit(job.resource_request()) {
            Some(permit) => {
                job.permit = permit;
                execute_job(job);
                break; // Job done, move to next
            }
            None => {
                // Resources exhausted: backoff strategy
                let delay = calculate_backoff(job.failures);
                queue.push_delayed(job, delay);
                break; // Try next job in queue
            }
        }
    }
}
```

### Interaction with ObjectFrontier

The Global Resource Pool and ObjectFrontier operate at different levels:

```
Scheduler Flow:
  Global Resource Pool (this module)
    ↓ hard cap on total memory across all jobs

  Job Execution Starts
    ↓
  ObjectFrontier (per-object concurrency control)
    ↓ caps concurrent blob fetches per object
    ↓ tracks memory per object

  Individual Blob Processing
```

**Key Insight**: Both limits can trigger backpressure:
- Global pool full -> job re-enqueued (intended integration behavior)
- ObjectFrontier full -> job waits for blob completions, then acquires next

---

## 6. Key Types and Functions

### `GlobalResourcePoolConfig`

**Purpose**: Immutable configuration for pool creation.

```rust
pub struct GlobalResourcePoolConfig {
    pub scan_ring_bytes: u64,      // Total bytes for scan rings
    pub delta_cache_bytes: u64,    // Total bytes for delta caches
    pub spill_slots: Option<usize>,// Concurrent spill ops (None = unlimited)
}
```

**Default Values**:
- `scan_ring_bytes`: 256 MB
- `delta_cache_bytes`: 512 MB
- `spill_slots`: Some(16)

**Methods**:
- `validate()` - Panics if config is invalid (zero budgets, etc.)

**Example**:
```rust
let config = GlobalResourcePoolConfig {
    scan_ring_bytes: 200 * 1024 * 1024,
    delta_cache_bytes: 400 * 1024 * 1024,
    spill_slots: Some(8),
};
config.validate();
```

### `GlobalResourcePool`

**Purpose**: Main resource manager; thread-safe via Arc<>.

**Thread Safety**: Safe to share via `Arc<GlobalResourcePool>`; all internal state uses atomic operations.

**Key Methods**:

#### `new(config: GlobalResourcePoolConfig) -> Arc<Self>`

Creates a new pool from configuration. Panics if config is invalid.

```rust
let pool = GlobalResourcePool::new(config);
// Returns Arc<GlobalResourcePool>
```

#### `try_acquire_fat_job_permit(request: FatJobRequest) -> Option<FatJobPermit>`

Attempts to acquire all requested resources. Returns `None` if any resource is unavailable; previously acquired resources are released.

**Acquisition order**:
1. Scan ring bytes
2. Delta cache bytes
3. Spill slot (if requested)

```rust
let permit = pool.try_acquire_fat_job_permit(
    FatJobRequest::git_repo(50, 100, true)
);

match permit {
    Some(p) => { /* resources acquired */ },
    None => { /* backoff and retry */ },
}
```

#### Monitoring Methods

- `scan_ring_available() -> u64` - Available scan ring bytes
- `scan_ring_total() -> u64` - Total scan ring capacity
- `delta_cache_available() -> u64` - Available delta cache bytes
- `delta_cache_total() -> u64` - Total delta cache capacity
- `spill_slots_available() -> Option<usize>` - Available spill slots (None if unlimited)
- `spill_slots_total() -> Option<usize>` - Total spill slots (None if unlimited)

**Usage**:
```rust
let avail_scan = pool.scan_ring_available();
let total_delta = pool.delta_cache_total();
let spill_capacity = pool.spill_slots_available();

if avail_scan < required_scan {
    // Not enough resources; skip this job
}
```

### `FatJobRequest`

**Purpose**: Describes resource requirements for a single job.

```rust
pub struct FatJobRequest {
    pub scan_ring_bytes: u64,
    pub delta_cache_bytes: u64,
    pub needs_spill_slot: bool,
}
```

**Helper Constructors**:

#### `git_repo(scan_ring_mb: u64, delta_cache_mb: u64, needs_spill: bool) -> Self`

Creates a request for Git repository scanning. Sizes in **megabytes**.

```rust
let request = FatJobRequest::git_repo(50, 100, true);
// 50 MB scan ring, 100 MB delta cache, spill enabled
```

**Panics** if MB values would overflow when converted to bytes.

#### `archive(max_file_size: u64, needs_spill: bool) -> Self`

Creates a request for archive extraction.

```rust
let request = FatJobRequest::archive(10 * 1024 * 1024, true);
// 10 MB scan ring, no delta cache, spill enabled
```

### `FatJobPermit`

**Purpose**: RAII guard holding acquired resources; automatically releases on drop.

**Attributes**:
- `#[must_use]` - Compiler warns if not used (prevents accidental resource leaks)

**Key Methods**:

#### `scan_ring_bytes() -> u64`

Returns the scan ring bytes held by this permit.

```rust
let bytes = permit.scan_ring_bytes();
assert_eq!(bytes, 50_000_000);
```

#### `delta_cache_bytes() -> u64`

Returns the delta cache bytes held by this permit.

```rust
let bytes = permit.delta_cache_bytes();
assert_eq!(bytes, 100_000_000);
```

#### `total_bytes() -> u64`

Returns sum of scan ring and delta cache bytes. Panics in debug builds on overflow.

```rust
let total = permit.total_bytes();
```

#### `can_spill() -> bool`

Returns true if the permit allows spilling:
- `true` if spill slot was acquired (limited) OR spilling is unlimited
- `false` if spill was not requested

```rust
if permit.can_spill() {
    enable_disk_spilling();
}
```

#### `spill_is_limited() -> bool`

Returns true only if spill slot is from a counted budget.

```rust
if permit.spill_is_limited() {
    log!("Spill is limited by configured slots");
}
```

**Drop Behavior**:

When permit is dropped:
1. Scan ring bytes are released to the pool
2. Delta cache bytes are released to the pool
3. Spill slot is released (if any) via CountPermit Drop
4. Debug assertions check for double-release or corruption

---

## 7. Performance Characteristics

### Operation Costs

| Operation                      | Implementation                                                                  | Cost                           |
| ------------------------------ | ------------------------------------------------------------------------------- | ------------------------------ |
| `try_acquire_fat_job_permit()` | 2 lock-free atomic CAS operations (byte budgets) + optional Mutex-guarded spill slot check | O(1), constant-time            |
| Release via Drop               | 2 byte-budget releases + optional spill-slot release                            | O(1), constant-time            |

### Scalability Notes

- **Job-level backpressure**: Designed for tens of acquisitions per second (job-level), not objects per second
- **Atomic contention**: Low contention because acquisitions are job-scoped, not per-object
- **No allocation**: FatJobPermit is stack-allocated (size guard: <= 80 bytes in tests)

### Memory Overhead

- `FatJobPermit` size: platform-dependent; unit test asserts it stays <= 80 bytes
- `GlobalResourcePool` size: platform-dependent (three Arc-backed budgets)
- Budget object sizes are implementation-dependent; avoid hard-coding byte counts

---

## 8. Known Limitations

### 1. No Fairness Guarantee

Large jobs may be starved by streams of small jobs:

```
Example: 200 MB pool, large job needs 120 MB
  - Small job A acquires 80 MB
  - Small job B acquires 80 MB → fails (only 40 MB left)
  - Small job B acquires 40 MB → succeeds

Large job keeps failing while small jobs complete and restart.
```

**Mitigation**: Scheduler should implement exponential backoff for failed large-job acquisitions (e.g., retry after 10ms → 20ms → 40ms).

### 2. No Wait Queue

Jobs that fail to acquire resources must re-enqueue themselves:

```rust
// No built-in waiting
match pool.try_acquire_fat_job_permit(request) {
    Some(permit) => { /* run job */ },
    None => {
        // Job must re-enqueue itself
        scheduler.enqueue_delayed(job, backoff_delay);
    }
}
```

This is consistent with `ObjectFrontier` design: jobs are re-enqueuable units.

### 3. No Dynamic Configuration

Pool configuration is set at creation time and cannot be changed. To adjust limits, the pool must be recreated and active permits must be released first.

### 4. Spill Concurrency Not Enforced

The `spill_slots` limit is a soft count; actual disk operations may exceed the slot count if job code doesn't respect `can_spill()`.

---

## 9. Testing

The module includes comprehensive tests covering:

### Basic Operations
- `basic_acquisition_and_release` - Acquire and release flow
- `empty_request_succeeds` - No-op requests work

### Correctness Invariants
- `global_pool_prevents_over_commit` - Pool prevents exceeding limits
- `partial_acquisition_releases_all` - Failed acquisitions don't leak
- `spill_slot_failure_releases_bytes` - Spill failures rollback bytes

### Spill Mode Variants
- `spill_only_request_acquires_slot` - Spill-only requests acquire slots
- `unlimited_spill_mode` - Unlimited spill configuration works

### Concurrency
- `concurrent_acquisition` - 10 threads acquire/release concurrently; pool fully restored

### Helper Constructors
- `git_repo_helper` - `FatJobRequest::git_repo()` builds correct request
- `archive_helper` - `FatJobRequest::archive()` builds correct request
- `permit_size_is_reasonable` - guards `FatJobPermit` size ceiling

### Configuration Validation
- Config validation rejects zero scan ring, delta cache, spill slots
- `git_repo()` helper rejects MB overflow

---

## 10. Configuration Guide

### Minimal (Conservative)

```rust
let config = GlobalResourcePoolConfig::default();
// 256 MB scan ring, 512 MB delta cache, 16 spill slots
```

### Small System (CI Runner)

```rust
let config = GlobalResourcePoolConfig {
    scan_ring_bytes: 100 * 1024 * 1024,     // 100 MB
    delta_cache_bytes: 200 * 1024 * 1024,   // 200 MB
    spill_slots: Some(4),
};
```

### Large System (Bulk Scanning)

```rust
let config = GlobalResourcePoolConfig {
    scan_ring_bytes: 1024 * 1024 * 1024,     // 1 GB
    delta_cache_bytes: 2048 * 1024 * 1024,   // 2 GB
    spill_slots: Some(32),
};
```

### Unlimited Spill

```rust
let config = GlobalResourcePoolConfig {
    scan_ring_bytes: 200 * 1024 * 1024,
    delta_cache_bytes: 400 * 1024 * 1024,
    spill_slots: None,  // Unlimited spilling
};
```

---

## 11. See Also

- `ByteBudget` (`crates/scanner-scheduler/src/scheduler/budget.rs`) - Per-resource byte budget with atomic tracking
- `CountBudget` (`crates/scanner-scheduler/src/scheduler/count_budget.rs`) - Counted slot budget (for spill concurrency)
- `ObjectFrontier` (`crates/scanner-scheduler/src/scheduler/task_graph.rs`) - Per-object concurrency and memory limits
- Scheduler resource-control modules (`crates/scanner-scheduler/src/scheduler/`) - module export is in place; runtime wiring is still pending
