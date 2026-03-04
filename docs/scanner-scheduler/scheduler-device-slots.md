# Device Slots: Per-Device I/O Concurrency Control

## Overview

The **Device Slots** module provides fairness control for mmap-based data sources (Git repositories, large archives) that share the same filesystem or mount point (`st_dev` on Unix). It prevents page cache thrashing and I/O collapse when multiple concurrent jobs perform memory-mapped operations on the same filesystem.

**Location:** `crates/scanner-scheduler/src/scheduler/device_slots.rs`

**Key Responsibility:** Limit concurrent mmap-heavy operations per storage device to maintain consistent throughput and prevent resource exhaustion.

---

## Problem Solved

When multiple jobs use mmap for pack file decoding or archive scanning, disk I/O occurs as page faults triggered by accessing mapped memory regions. This bypasses the scheduler's explicit in-flight read accounting because page faults are kernel-driven and implicit.

Without limits, this leads to:
- **Page cache thrashing**: Too many concurrent mmap regions cause eviction cycles
- **I/O collapse**: Disk scheduling becomes chaotic with interleaved random seeks
- **Throughput degradation**: System spends time context-switching between page faults rather than making progress

Device slots solve this by providing **coarse-grained admission control** that limits how many mmap-heavy jobs can run concurrently on each device.

---

## Device Classes and Identification

### DeviceId

```rust
pub struct DeviceId(u64);
```

Device identification follows platform conventions:

#### Unix (Linux, macOS)
- Uses `st_dev` from `stat(2)` system call
- Identifies filesystem/mount point, not physical disk
- Obtained via `DeviceId::from_path()` or `DeviceId::try_from_path()`

#### Non-Unix (Windows)
- Falls back to `DeviceId::UNKNOWN` (single global pool)
- All paths on unknown devices serialize through one slot pool
- Future enhancement: Use `GetVolumeInformationByHandleW` for Windows volumes

#### Unknown Device Fallback
- Sentinel value: `u64::MAX`
- Used when path doesn't exist, permissions denied, or platform unsupported
- All unknown devices share a single slot pool (safe but potentially suboptimal)

### Device Categorization

Devices are **not explicitly categorized** by type (HDD, NVMe, etc.). Instead:
- All devices receive a default slot count (typically 4)
- Per-device overrides allow tuning for specific devices
- Configuration is static at allocator creation time

**Example Configuration:**
```rust
let config = DeviceSlotsConfig::uniform(4)
    .with_device(fast_nvme, 8)  // More slots for fast storage
    .with_device(slow_hdd, 2);  // Fewer slots for slow storage

let slots = DeviceSlots::new(config);
```

---

## Slot Allocation Strategy

### Fair Allocation Algorithm

The device slots system implements **per-device admission control**:

1. **Per-Device Budgets**: Each unique `DeviceId` gets an independent `CountBudget`
2. **Lazy Initialization**: Budgets created on first access to a device
3. **Slot Limits**: Budget size = configured slots for that device
4. **No strict waiter ordering**: `try_acquire()` is non-blocking and `acquire()` waits via condvar; fairness comes from bounded per-device concurrency, not FIFO guarantees

### Slot Lifecycle

```
┌──────────────────────────────┐
│   DeviceSlots (per allocator)│
├──────────────────────────────┤
│ HashMap<DeviceId, CountBudget>
│  ├─ Device A: CountBudget(4 slots)
│  ├─ Device B: CountBudget(2 slots)
│  └─ Device Unknown: CountBudget(4 slots)
└──────────────────────────────┘
            │
            ├─ try_acquire(device) → Option<DeviceSlotPermit>
            │  (non-blocking, returns None if no slots available)
            │
            └─ acquire(device) → DeviceSlotPermit
               (blocking, waits until slot available)
```

### Acquisition Methods

| Method                       | Behavior                             | Use Case                             |
| ---------------------------- | ------------------------------------ | ------------------------------------ |
| `try_acquire(device)`        | Non-blocking, returns `None` if full | Worker threads (re-queue on failure) |
| `acquire(device)`            | Blocking, waits for available slot   | Discovery threads, initialization    |
| `try_acquire_for_path(path)` | Auto-detect device, then try_acquire | Convenience, but performs `stat(2)`  |

### RAII Permits

```rust
pub struct DeviceSlotPermit {
    inner: CountPermit,
    device: DeviceId,
}
```

- Acquired via `try_acquire()` or `acquire()`
- Holds one slot for the duration of scope
- Automatically released when dropped
- Must be held throughout mmap-heavy operations

---

## Backpressure Mechanism

Device slots implement backpressure to prevent overwhelming devices:

### How Backpressure Works

1. **Capacity Check**: When a job attempts `try_acquire(device)`, scheduler checks if device budget has available slots

2. **Rejection**: If budget is exhausted (`available() == 0`), return `None`
   - Job is NOT acquired
   - No slot is consumed

3. **Requeue**: Scheduler re-enqueues the job for later retry
   - Allows other jobs to progress
   - Prevents thread blocking in worker pool

4. **Recovery**: When any job completes and releases its permit, a slot becomes available
   - Waiting jobs can now acquire

### Backpressure in Action

```
Time │ Device Slots (limit: 3)  │ Queue                │ Action
─────┼─────────────────────────┼──────────────────────┼─────────────────────
  T1 │ [Job₁][Job₂][Job₃]     │ [Job₄, Job₅]        │ Device full
  T2 │ [Job₁][Job₂][ ]        │ [Job₅, Job₄]        │ Job₃ completes
  T3 │ [Job₁][Job₂][Job₄]     │ [Job₅]               │ Job₄ acquires slot
  T4 │ [Job₂][Job₄][Job₅]     │ []                   │ Job₅ acquires slot
```

### Contract: Advisory Fairness, Not Hard I/O Cap

**Important distinction:**

| Aspect                     | Device Slots | Doesn't Control        |
| -------------------------- | ------------ | ---------------------- |
| Concurrent jobs per device | ✓ Limited    | Actual disk I/O timing |
| Admission control          | ✓ Yes        | Page fault rates       |
| Per-device fairness        | ✓ Yes        | Page cache eviction    |
|                            |              | Kernel scheduling      |

Device slots are **advisory**—they limit concurrency but don't enforce hard I/O bandwidth limits. The kernel still makes final decisions about page cache management and I/O scheduling.

---

## Integration with Backend Systems

Current status: this module defines the contract and API, but scheduler backends are not yet wired to call `DeviceSlots` directly in production paths.

### Local Backend Integration

**mmap-Based Sources** (Git pack files, large archives):
1. Detect device: `device = DeviceId::from_path(repo_path)`
2. Acquire permit: `permit = slots.try_acquire(device)?`
3. Hold permit: Store in job struct for lifetime of mmap operations
4. Release: Permit auto-releases when job completes

**Explicit I/O Sources** (files with io_uring):
- Do NOT use device slots
- Use read token permits instead
- Scheduler controls buffer pool and bytes-in-flight

### Remote Backend Integration

**S3, HTTP, and remote sources:**
- Do NOT use device slots
- Use explicit read tokens through I/O engine
- Scheduler controls connection concurrency and bytes-in-flight

### I/O Model Enum

> **Source of truth:** `device_slots.rs`

The `IoModel` enum determines which resource limits apply to a given source:

```rust
pub enum IoModel {
    /// Explicit reads through scheduler's I/O stage.
    /// Does NOT use device slots; uses read tokens instead.
    ExplicitReads,

    /// Mmap-based I/O with implicit page faults.
    /// Uses device slots for concurrency control; does NOT use read tokens.
    MmapImplicit,
}

impl IoModel {
    pub fn uses_device_slots(&self) -> bool { matches!(self, IoModel::MmapImplicit) }
    pub fn uses_read_tokens(&self) -> bool { matches!(self, IoModel::ExplicitReads) }
}
```

**Scheduler Decision Logic:**
```rust
let io_model = source.io_model();
if io_model.uses_device_slots() {
    let permit = device_slots.try_acquire(device)?;
    scan_with_mmap(repo, permit);
} else {
    let token = read_tokens.try_acquire()?;
    scan_with_explicit_reads(source, token);
}
```

---

## Key Types and Functions

### Configuration

#### `DeviceSlotsConfig`
```rust
pub struct DeviceSlotsConfig {
    pub default_slots: usize,
    pub device_overrides: HashMap<DeviceId, usize>,
}

impl DeviceSlotsConfig {
    pub fn uniform(slots: usize) -> Self
    pub fn with_device(self, device: DeviceId, slots: usize) -> Self
}
```

| Method                   | Purpose                                      |
| ------------------------ | -------------------------------------------- |
| `uniform(n)`             | Create config with `n` slots for all devices |
| `with_device(device, n)` | Override slots for specific device           |

**Validation:** Panics if any slot count is zero.

### Allocator

#### `DeviceSlots`
```rust
pub struct DeviceSlots { /* internal */ }

impl DeviceSlots {
    pub fn new(config: DeviceSlotsConfig) -> Arc<Self>
    pub fn uniform(slots: usize) -> Arc<Self>

    pub fn try_acquire(self: &Arc<Self>, device: DeviceId) -> Option<DeviceSlotPermit>
    pub fn acquire(self: &Arc<Self>, device: DeviceId) -> DeviceSlotPermit
    pub fn try_acquire_for_path(self: &Arc<Self>, path: &Path) -> Option<DeviceSlotPermit>

    pub fn available(&self, device: DeviceId) -> Option<usize>
    pub fn total(&self, device: DeviceId) -> usize
    pub fn active_device_count(&self) -> usize
}
```

| Method                   | Returns          | Purpose                                             |
| ------------------------ | ---------------- | --------------------------------------------------- |
| `new()`                  | `Arc<Self>`      | Create allocator with custom config                 |
| `uniform()`              | `Arc<Self>`      | Create allocator with uniform slots                 |
| `try_acquire()`          | `Option<Permit>` | Non-blocking slot acquisition                       |
| `acquire()`              | `Permit`         | Blocking slot acquisition                           |
| `try_acquire_for_path()` | `Option<Permit>` | Auto-detect device + acquire                        |
| `available()`            | `Option<usize>`  | Check free slots (or None if device never accessed) |
| `total()`                | `usize`          | Get total slots for device                          |
| `active_device_count()`  | `usize`          | Count devices with active budgets                   |

#### `DeviceSlotPermit`
```rust
pub struct DeviceSlotPermit { /* internal */ }

impl DeviceSlotPermit {
    pub fn device(&self) -> DeviceId
}
```

RAII permit that releases slot on drop.

### Device Identification

#### `DeviceId`
```rust
pub struct DeviceId(u64);

impl DeviceId {
    pub const UNKNOWN: DeviceId = DeviceId(u64::MAX);

    pub fn from_path(path: &Path) -> Self
    pub fn try_from_path(path: &Path) -> std::io::Result<Self>
    pub fn from_raw(raw: u64) -> Self

    pub fn raw(&self) -> u64
    pub fn is_unknown(&self) -> bool
}
```

| Method            | Platform                            | Returns                  |
| ----------------- | ----------------------------------- | ------------------------ |
| `from_path()`     | Unix: `st_dev`, Non-Unix: `UNKNOWN` | `DeviceId`               |
| `try_from_path()` | Unix: Result, Non-Unix: Always Ok   | `Result`                 |
| `from_raw()`      | All                                 | `DeviceId` (for testing) |
| `is_unknown()`    | All                                 | `bool`                   |

---

## Performance Considerations

### Thread Safety
- Safe to share via `Arc<DeviceSlots>`
- Internal budgets protected by `std::sync::Mutex`
- Poison recovery ensures continued operation if thread panics

### Memory Overhead
- `DeviceSlotPermit` size is tested to stay <= 48 bytes
- Budget map grows monotonically (acceptable for CI/CD, problematic for long-running daemons)
- No automatic cleanup of unused devices

### Syscall Cost
- `DeviceId::from_path()` calls `stat(2)` on Unix
- Cache device IDs at job discovery time
- Avoid repeated calls in hot paths

### Example: Efficient Pattern
```rust
// Discovery phase (cached)
let device = DeviceId::from_path(repo_path);  // Calls stat(2) once

// Scheduler hot path (cheap lookup)
loop {
    if let Some(permit) = slots.try_acquire(device) {  // O(1), no syscall
        // proceed with job
    }
}
```

---

## Limitations and Future Work

### 1. Filesystem Identity vs Physical Device

**Current:**
- Uses `st_dev` (filesystem/mount identity)
- Different partitions on same disk get separate slot pools

**Future Improvement:**
- Map partitions to physical devices using OS-specific APIs
- Linux: sysfs (`/sys/dev/block/`)
- macOS: IOKit
- Windows: `GetVolumeInformationByHandleW`

### 2. Budget Map Growth

**Current:**
- Budget map grows monotonically
- No cleanup of unused devices

**Acceptable For:**
- CI/CD with stable device sets
- Short-lived processes

**Problem For:**
- Long-running daemons with ephemeral mounts
- Temporary mountpoints added/removed frequently

**Future Improvement:**
- Periodic pruning of unused devices
- LRU eviction for unused budgets

### 3. Windows Support

**Current:**
- Falls back to `UNKNOWN` device (single global pool)
- All paths on Windows serialize through one pool

**Trade-off:**
- Safe but suboptimal (serializes even on different volumes)
- No false positives (won't over-subscribe a device)

---

## When to Use Device Slots

### Use When:
- ✓ Source uses mmap for data access (Git pack files, archives)
- ✓ Multiple concurrent jobs may target same filesystem
- ✓ Page cache pressure is a concern
- ✓ Need fairness across devices

### Don't Use When:
- ✗ Source uses explicit reads (io_uring, HTTP)
- ✗ Jobs are known to be on different filesystems
- ✗ Memory is sufficient to cache all working sets
- ✗ Single-threaded or single-device workload

---

## Testing

The module includes comprehensive tests covering:

- **Basic Slot Lifecycle**: Acquisition, release, availability tracking
- **Multi-Device Isolation**: Different devices have independent pools
- **Configuration Overrides**: Per-device slot customization
- **Unknown Device Handling**: Fallback behavior
- **Concurrent Access**: Thread-safe acquisition with barriers
- **Blocking Semantics**: Proper wait and wake behavior
- **RAII Correctness**: Permits auto-release on drop
- **Device Detection**: Real filesystem detection (Unix)
- **Error Cases**: Invalid configurations panic as expected

**Key Test:** `concurrent_acquisition_with_barrier` verifies that concurrent threads never exceed slot limit.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│ Scheduler                                               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Job Discovery              Job Execution              │
│  ┌─────────────────────┐  ┌─────────────────────┐     │
│  │ for each job:       │  │ worker_thread:      │     │
│  │  device = from_path │  │  if try_acquire()   │     │
│  │  cache(device)      │  │    run_job()        │     │
│  └────────┬────────────┘  │  else:              │     │
│           │                │    requeue_job()    │     │
│           └────────────────┤                     │     │
│                            └────────┬────────────┘     │
│                                     │                  │
│  ┌───────────────────────────────────┴──────────────┐ │
│  │              DeviceSlots                         │ │
│  ├──────────────────────────────────────────────────┤ │
│  │ HashMap<DeviceId, CountBudget>                   │ │
│  │  ├─ /dev (st_dev=1001) → CountBudget(4)         │ │
│  │  ├─ /mnt/storage → CountBudget(2)               │ │
│  │  └─ UNKNOWN → CountBudget(4)                    │ │
│  └──────────────────────────────────────────────────┘ │
│           │                                             │
│           ├─ Fairness: Each device independent        │
│           ├─ Advisory: No hard I/O enforcement        │
│           └─ RAII: Permits auto-release              │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Summary

Device slots provide **fair, device-level admission control** for mmap-based sources:

- **Per-device budgets** ensure fairness across storage devices
- **Backpressure mechanism** prevents overwhelming page cache
- **RAII permits** guarantee slot release even on exception
- **Advisory fairness** complements kernel I/O scheduling
- **Platform-aware** with graceful fallbacks for unsupported systems
- **Extensible configuration** supports per-device tuning

This allows the scheduler to maintain consistent throughput when multiple jobs perform memory-mapped data access to shared storage.
