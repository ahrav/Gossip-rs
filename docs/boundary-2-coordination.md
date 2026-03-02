# Boundary 2 -- Shard Coordination Protocol

## 1. Overview

Boundary 2 (Shard Coordination Protocol) manages distributed shard lifecycle,
lease-based ownership, and bounded idempotent operations for the gossip-rs
secret scanner. The shared data model (shard spec, cursor, pooled wrappers,
manifest validation, split-replace planning core) lives in
`crates/gossip-contracts/src/coordination/`, and the protocol layer
(traits, state machine, InMemoryCoordinator, sim harness)
lives in `crates/gossip-coordination/src/`. Both depend on Boundary 1
(Identity & Hashing Spine) for `TenantId`, `ShardId`, `RunId`, `OpId`,
`FenceEpoch`, `LogicalTime`, and `CanonicalBytes`.

The module provides six core capabilities:

- **Shard lifecycle state machine** -- a four-state automaton (`Active`,
  `Done`, `Split`, `Parked`) with terminal state enforcement and
  compile-time discriminant stability.
- **Lease-based ownership with fencing tokens** -- time-bounded exclusive
  access enforced by monotonic `FenceEpoch` values that reject zombie
  workers (Kleppmann 2016).
- **Bounded idempotency** -- a 16-entry FIFO op-log backed by `RingBuffer`
  that caches operation fingerprints for replay detection, inspired by
  Stripe's idempotency key pattern.
- **Deterministic split operations** -- two strategies (replace and residual)
  that produce child shard IDs via domain-separated BLAKE3, with full
  coverage validation.
- **Run-level management** -- two-phase creation (`create_run` then
  `register_shards`), progress aggregation, and terminal transitions with
  their own bounded op-log.
- **Tiger-style invariant enforcement** -- crash-to-prevent-corruption
  philosophy where violated invariants panic before persistence, ensuring
  crash-recovery returns to the last valid state.
- **Assignment handoff boundary** -- coordination emits shard assignments
  that runtime layers translate through `gossip-scan-driver`
  (`ScanSourceFactory` + `ScanDriver`) so CLI and distributed execution share
  one scanner-scheduler/engine path.

### Source files

| File            | Role                                                                  |
|-----------------|-----------------------------------------------------------------------|
| `traits.rs`     | `CoordinationBackend` trait -- the semantic contract for all backends |
| `record.rs`     | `ShardRecord`, `ShardStatus`, `ParkReason`, `ShardSnapshotView`       |
| `run.rs`        | `RunRecord`, `RunStatus`, `RunConfig`, `RunManagement` trait          |
| `gossip-contracts::coordination/split.rs` | Contracts-owned split planner core (`SplitReplacePlan`, `SplitResidualPlan`, `plan_split_replace*`, `plan_split_residual*`) |
| `split_execution.rs` | Coordination-owned split execution helpers: derived shard IDs, payload hashing, result types |
| `in_memory.rs`  | In-memory reference implementation (executable spec)                  |
| `lease.rs`      | `Lease`, `LeaseHolder`, `OpLogEntry`, `OpKind`, `OpResult`            |
| `cursor.rs`     | `Cursor` type with monotonicity and bounds semantics                  |
| `shard_spec.rs` | `ShardSpec` key-range type, `CursorSemantics`, split validation       |
| `pooled.rs`     | `PooledShardSpec`, `PooledCursor` — arena-pooled byte-field wrappers |
| `limits.rs`     | Capacity constants for split fan-out (`MAX_SPLIT_CHILDREN`, `MAX_SPAWNED_PER_SHARD`) |
| `manifest.rs`   | `InitialShardInput`, `validate_manifest` — shard manifest validation for `register_shards` |
| `error.rs`      | Shared `CoordError` and `IdempotentOutcome`                           |
| `run_errors.rs` | Run-management error types                                            |
| `validation.rs` | `validate_lease`, `validate_cursor_update_pooled`, `check_op_idempotency` |
| `events.rs`     | `EventCollector`, `EventKind`, `StateTransitionEvent`                 |
| `facade.rs`     | `CoordinationFacade`, `ShardClaiming`, `ClaimError`                   |
| `session.rs`    | `WorkerSession` ergonomic wrapper with move/borrow lifecycle          |
| `lib.rs`        | Module root and public re-exports                                     |

---

## 2. Shard State Machine

```text
                 ┌──────────────┐
                 │    Active    │
                 └──┬───┬───┬──┘
                    │   │   │
         Complete   │   │   │  Park
           ┌────────┘   │   └────────┐
           ▼            │            ▼
      ┌────────┐   SplitReplace  ┌────────┐
      │  Done  │        │        │ Parked │
      └────────┘        ▼        └────────┘
                   ┌────────┐
                   │ Split  │
                   └────────┘
```

### Transition rules

All transitions originate from `Active`. `Done`, `Split`, and `Parked` are
**terminal** within the coordination protocol -- once a shard reaches one of
these states, no `CoordinationBackend` operation may change its status. The
method `ShardRecord::assert_transition_legal` panics on any attempt to
transition from a terminal state to a different state.

`Parked` has one escape hatch: `unpark_shard` (via the `RunManagement` trait,
**not** `CoordinationBackend`) transitions `Parked` back to `Active` and bumps
the fence epoch to invalidate any zombie workers from a prior lease.

`split_residual` is special: it shrinks the parent's key range and spawns a
residual child shard, but the **parent stays `Active`**. It is the only split
strategy that does not retire the parent.

### ShardStatus discriminants

`ShardStatus` uses `#[repr(u8)]` with stable discriminants that are persisted
to durable storage. Compile-time assertions enforce the mapping:

| Variant  | Discriminant | Terminal? |
|----------|:------------:|:---------:|
| `Active` | 0            | No        |
| `Done`   | 1            | Yes       |
| `Split`  | 2            | Yes       |
| `Parked` | 3            | Yes       |

### ParkReason

When a shard is parked, a `ParkReason` (`#[repr(u8)]`) is stored alongside:

| Variant            | Discriminant | Meaning                                                     |
|--------------------|:------------:|-------------------------------------------------------------|
| `PermissionDenied` | 0            | Connector lacks access -- requires credential rotation      |
| `NotFound`         | 1            | Scan target no longer exists                                |
| `Poisoned`         | 2            | Internal inconsistency -- requires manual investigation     |
| `TooManyErrors`    | 3            | Transient errors accumulated -- suitable for auto-retry     |
| `Other`            | 4            | Catch-all; backend should log additional context separately |

The invariant `park_reason.is_some()` iff `status == Parked` is asserted on
every state transition via `assert_invariants`.

---

## 3. Op-log Pattern

The coordination protocol uses **bounded idempotency** -- a short-term
operation cache that allows workers to safely retry RPCs without causing
duplicate side effects.

### Structure

Each shard carries a 16-entry FIFO op-log implemented as
`RingBuffer<OpLogEntry, 16>`. Each entry stores five fields:

```text
(OpId, OpKind, OpResult, payload_hash: u64, executed_at: LogicalTime)
```

- **`OpId`**: CSPRNG-generated idempotency key (unique per operation)
- **`OpKind`**: discriminant identifying the operation type (`Checkpoint`,
  `Complete`, `Park`, `SplitReplace`, `SplitResidual`, `Unpark`)
- **`OpResult`**: stored outcome (`Completed`, `Error`, `Superseded`)
- **`payload_hash`**: BLAKE3 fingerprint of the operation's parameters
- **`executed_at`**: logical timestamp of first execution

### Replay detection tiers

When an operation arrives with `(op_id, payload_hash)`:

1. **Same `(op_id, payload_hash)`** -- the op-log entry matches. Return the
   cached result as `IdempotentOutcome::Replayed`. No mutation occurs.
2. **Same `op_id`, different `payload_hash`** -- the caller reused an OpId
   with different parameters. Return `OpIdConflict` error. This is always a
   client bug.
3. **New `op_id`** (not in the op-log) -- execute the operation, record the
   result in the op-log, return `IdempotentOutcome::Executed`.

Idempotency is checked **before** lease validation on every idempotent path,
so that replays succeed even after the lease has expired or the shard has
reached a terminal status.

### Eviction semantics

When the op-log reaches capacity (16 entries), the oldest entry is evicted via
O(1) ring buffer overwrite (`push_back_overwrite`). After eviction, the
coordinator can no longer detect a retry for that `OpId` and treats it as a
new operation.

Post-eviction re-execution is safe because:

1. **Staleness guarantee** -- eviction implies the `OpId` is at least 16
   operations old, well past any reasonable retry window.
2. **Convergent state transitions** -- re-executing a shard operation either
   converges to the same terminal state or is rejected by status guards
   (e.g., completing an already-`Done` shard).
3. **`FenceEpoch` is the primary zombie defense** -- the op-log is a
   secondary defense for in-lease retries only. A stale worker from a prior
   lease epoch is fenced out by epoch comparison before the op-log is ever
   consulted.

### Payload hashing

Payload hashes use domain-separated BLAKE3 via the `OP_PAYLOAD_V1` domain
constant, with per-operation tags prepended as a second domain-separation
layer:

| Operation        | Tag bytes           | Hashed fields                                 |
|------------------|---------------------|-----------------------------------------------|
| `checkpoint`     | `b"checkpoint"`     | `Cursor` (via `CanonicalBytes`)               |
| `complete`       | `b"complete"`       | `Cursor` (via `CanonicalBytes`)               |
| `park`           | `b"park"`           | `ParkReason` (via `CanonicalBytes`)           |
| `split_replace`  | `b"split_replace"`  | `SplitReplacePlan` (length-prefixed children) |
| `split_residual` | `b"split_residual"` | `SplitResidualPlan` (parent + residual specs) |

The per-operation tag ensures that a checkpoint and a complete with the same
cursor produce different hashes.

### Why RingBuffer

| Data Structure    | Rejection Reason                                              |
|-------------------|---------------------------------------------------------------|
| `Vec`             | O(n) eviction via `remove(0)` -- slides all elements          |
| `VecDeque`        | Heap-allocated -- violates zero-alloc hot-path requirement    |
| `ArrayVec`        | No ring semantics -- eviction requires manual shift           |
| `Option<T>` array | 25% memory overhead for empty slots; manual index bookkeeping |

`RingBuffer` provides O(1) push/evict, stack-allocated `[MaybeUninit<T>; N]`
storage, and power-of-2 bitwise index calculation.

---

## 4. Run Lifecycle

```text
 Initializing ──register_shards──→ Active
      │                              │
      │ cancel_run          ┌────────┼────────┐
      ▼                 complete fail_run  cancel
   Cancelled                │        │        │
                            ▼        ▼        ▼
                          Done    Failed  Cancelled
```

A "run" is a single scan invocation -- it groups a set of shards that
collectively cover the target data source. The coordinator tracks run status,
validates shard manifests, and provides progress aggregation.

### RunStatus discriminants

`RunStatus` uses `#[repr(u8)]` with stable discriminants:

| Variant        | Discriminant | Terminal? |
|----------------|:------------:|:---------:|
| `Initializing` | 0            | No        |
| `Active`       | 1            | No        |
| `Done`         | 2            | Yes       |
| `Failed`       | 3            | Yes       |
| `Cancelled`    | 4            | Yes       |

### Two-phase creation

Run creation is a two-phase process (D2.20):

1. **`create_run(tenant, run_id, config)`** -- creates a `RunRecord` in
   `Initializing` status with no shards. The `RunConfig` carries
   `cursor_semantics`, `lease_duration`, and `max_shard_retries`.
2. **`register_shards(tenant, run_id, shards, op_id)`** -- validates the
   shard manifest (uniqueness, non-empty, bounded key ranges), creates
   `ShardRecord` entries, and transitions the run to `Active`. This step
   is idempotent via `OpId`.

### RunRecord

`RunRecord` is the coordinator's authoritative record for a run. It contains:

- Identity: `tenant`, `run` (RunId)
- Configuration: `config` (RunConfig)
- Lifecycle: `status` (RunStatus), `created_at`, `completed_at`
- Shard manifest: `root_shards` (Vec of ShardId)
- Idempotency: `op_log` (RingBuffer of RunOpLogEntry, cap: 8)

### RunManagement trait

`RunManagement` is a separate trait from `CoordinationBackend` (D2.22). It
defines run-level and admin operations:

| Method             | Description                           | Idempotent? | Lease-gated? |
|--------------------|---------------------------------------|:-----------:|:------------:|
| `create_run`       | Create run in Initializing status     | No          | No           |
| `register_shards`  | Populate shards, transition to Active | Yes (OpId)  | No           |
| `get_run`          | Return run record (read-only)         | N/A         | No           |
| `get_run_progress` | Aggregate shard status counts         | N/A         | No           |
| `list_shards`      | Return filtered shard summaries       | N/A         | No           |
| `complete_run`     | Transition Active to Done             | Yes (OpId)  | No           |
| `fail_run`         | Transition Active to Failed           | Yes (OpId)  | No           |
| `cancel_run`       | Transition non-terminal to Cancelled  | Yes (OpId)  | No           |
| `unpark_shard`     | Resume Parked shard to Active         | Yes (OpId)  | No           |

Admin operations (`unpark`, `cancel`) are **not** lease-gated (D2.21) -- they
are coordinator-level actions that do not require a worker to hold a lease.

---

## 5. Split Operations

When a shard's key range becomes too large or unevenly distributed, the
coordinator splits it into smaller shards. Two strategies exist:

### Split-replace

The parent is retired (status transitions to `Split`) and replaced by >= 2
children that collectively cover the parent's entire key range.

**Execution phases:**
1. **Validate** -- idempotency check, lease validation, full-coverage
   validation via `validate_split_coverage`, spawn-cap guard.
2. **Build** -- derive deterministic child IDs via `derive_split_shard_id`
   with `DerivedShardKind::Child` and sequential indices starting at
   `parent.spawned.len()`. Construct child `ShardRecord` entries.
3. **Apply** -- transition parent to `Split` (terminal), insert children
   into the map, update run-shard index.

After split-replace, the parent is terminal. No further operations can push
op-log entries, so the split-replace op-log entry is **never evicted** --
guaranteeing idempotent replay detection forever.

### Split-residual

The parent shrinks its key range (stays `Active`) and a new residual shard
covers the remainder. The parent keeps its lease and continues processing.

**Execution phases:**
1. **Validate** -- idempotency (two-tier: op-log primary, `spawned` probe
   as defense-in-depth), lease validation, coverage validation via
   `validate_residual_split`, cursor-bounds check (parent's cursor must
   remain within shrunk range), spawn-cap guard.
2. **Build** -- derive residual ID via `derive_split_shard_id` with
   `DerivedShardKind::Residual`. Residual starts with `Cursor::initial()`.
3. **Apply** -- update parent's spec and `spawned` list, insert residual
   into map, update run-shard index. Parent keeps its lease.

Because the parent stays `Active`, subsequent operations can evict the
split-residual op-log entry. The `find_replayed_residual` function provides
a secondary replay detection path by scanning `parent.spawned` for a
residual derived from the same `OpId`.

### Derived shard IDs

Child and residual shard IDs are derived deterministically via
`derive_split_shard_id`, which uses domain-separated BLAKE3 (`SPLIT_ID_V1`)
with five inputs: `(run, parent_shard, op_id, kind, index)`. The output has
**bit 63 set** to distinguish derived shards from externally-assigned root
shards.

Birthday collision bound: ~2^31.5 values before 50% collision probability
(63 effective bits). Acceptable for coordination use cases where the total
number of derived shards per run is bounded.

### Constants

| Constant                | Value | Purpose                                            |
|-------------------------|:-----:|----------------------------------------------------|
| `MAX_SPLIT_CHILDREN`    | 256   | Maximum children in a single split-replace         |
| `MAX_SPAWNED_PER_SHARD` | 1024  | Maximum cumulative children + residuals per parent |

Compile-time assertion: `MAX_SPLIT_CHILDREN <= MAX_SPAWNED_PER_SHARD`.

### Memory-safety pattern

Both split operations use the **remove-mutate-restore** pattern: the parent
record is temporarily removed from the `HashMap`, mutated inside a closure,
then restored on both success and failure paths. This avoids holding a
`&mut ShardRecord` (from `get_mut`) while also inserting new child entries
into the same `HashMap`. If the closure panics (invariant violation), the
parent is intentionally *not* restored -- an invariant panic indicates
irrecoverable corruption.

---

## 6. Lease and Fencing Protocol

### Lease structure

A `Lease` is the capability returned by `acquire_and_restore_into` and required by
all lease-gated mutations. It contains:

- `tenant: TenantId` -- tenant isolation scope
- `run: RunId`, `shard: ShardId` -- shard identity
- `owner: WorkerId` -- the worker holding the lease
- `fence: FenceEpoch` -- monotonically increasing epoch (fencing token)
- `deadline: LogicalTime` -- expiry time

Fields are private -- the coordinator constructs leases and workers read them
via accessors.

### Fencing token protocol

Every `acquire_and_restore_into` increments the shard's `fence_epoch`. Subsequent
mutations must present a lease whose `fence` matches the record's current
epoch. If the epoch does not match, the operation is rejected with
`StaleFence` -- the worker is a zombie from a prior ownership period.

This is the "fencing token protocol" from Kleppmann (2016): all writes carry
the fence epoch, and the backend rejects stale epochs.

### Lease validation order

`validate_lease` checks preconditions in priority order to prevent information
leakage:

1. **Tenant isolation** (SEC-1) -- wrong-tenant requests are rejected before
   any internal state is revealed
2. **Terminal status** -- fast rejection of dead shards
3. **Fence epoch** -- zombie fencing
4. **Lease expiry** -- time-based rejection (`now >= deadline`)
5. **Owner divergence** -- catches identity mismatches when epochs agree

### LeaseHolder

`LeaseHolder` bundles `owner: WorkerId` and `deadline: LogicalTime` into a
single value so that `ShardRecord` can store `Option<LeaseHolder>` instead of
two separate `Option` fields -- making the "both-present-or-both-absent"
invariant structurally impossible to violate.

---

## 7. Tiger-style Invariant Enforcement

The coordination protocol follows the **crash-to-prevent-corruption**
philosophy: a violated invariant panics immediately, the operation is NOT
persisted, and on crash-recovery the shard returns to its pre-operation state.

Every mutation path calls `ShardRecord::assert_invariants()` before returning.
`RunRecord::assert_invariants()` performs analogous checks at the run level.

### The 10 ShardRecord invariants

| #  | Invariant                                               | Check                                                                 |
|----|---------------------------------------------------------|-----------------------------------------------------------------------|
| 1  | `park_reason.is_some()` iff `status == Parked`          | Status-reason consistency                                             |
| 2  | _(structural)_                                          | `Option<LeaseHolder>` makes paired-ness implicit                      |
| 3  | Terminal shards must not hold a lease                   | `status.is_terminal()` implies `lease.is_none()`                      |
| 4  | `fence_epoch >= FenceEpoch::INITIAL`                    | Fence epoch minimum (>= 1)                                            |
| 5  | `op_log.len() <= OP_LOG_CAP`                            | Op-log bounded (defense-in-depth; `RingBuffer` enforces structurally) |
| 6  | `status == Split` implies `!spawned.is_empty()`         | Split shards must have children                                       |
| 7  | `parent.is_some()` iff `shard.is_derived()`             | Biconditional: bit 63 set iff has parent                              |
| 8  | All entries in `spawned` satisfy `is_derived() == true` | Spawned children must be derived                                      |
| 9  | Op-log entries have unique `OpId` values                | No duplicate idempotency keys                                         |
| 10 | `spawned.len() <= MAX_SPAWNED_PER_SHARD`                | Spawned count bounded at 1024                                         |

INV-9 is O(n^2) where n <= 16 (at most 120 comparisons) -- dominated by
the per-transition persistence cost.

The core safety properties (mutual exclusion, zombie rejection, fence
monotonicity, terminal irreversibility, split atomicity, and cursor
monotonicity) are also verified exhaustively by the TLA+ model checker
across all reachable states. See
[specs/coordination/README.md](../specs/coordination/README.md) for the
specification, property mapping, and instructions for running TLC.

### Operational guidance

Invariant panics should be treated as critical bugs. Monitor for coordinator
process crashes and alert immediately. The shard's durable state is safe (the
failing operation was not persisted), but the root cause must be investigated.

---

## 8. CoordinationBackend Contract

The core trait with 7 operations that every backend (in-memory, FoundationDB,
PostgreSQL, deterministic simulator) must implement:

| Operation             | Signature                                          | Terminal?    | Idempotent? | Lease-gated? |
|-----------------------|----------------------------------------------------|:------------:|:-----------:|:------------:|
| `acquire_and_restore_into` | `(now, tenant, key, worker) -> (Lease, Snapshot)`  | No           | No          | No           |
| `renew`               | `(now, tenant, lease) -> new_deadline`             | No           | No          | Yes          |
| `checkpoint`          | `(now, tenant, lease, cursor, op_id) -> ()`        | No           | Yes (OpId)  | Yes          |
| `complete`            | `(now, tenant, lease, cursor, op_id) -> ()`        | Yes (Done)   | Yes (OpId)  | Yes          |
| `park_shard`          | `(now, tenant, lease, reason, op_id) -> ()`        | Yes (Parked) | Yes (OpId)  | Yes          |
| `split_replace`       | `(now, tenant, lease, plan, op_id) -> child_ids`   | Yes (Split)  | Yes (OpId)  | Yes          |
| `split_residual`      | `(now, tenant, lease, plan, op_id) -> residual_id` | No           | Yes (OpId)  | Yes          |

### Operation semantics

**`acquire_and_restore_into`** -- the entry point for a worker to start or resume
scanning. Verifies the shard is Active and unleased (or lease expired),
increments `fence_epoch`, grants a new lease, and returns a `ShardSnapshot`
with the shard's last checkpointed cursor. NOT idempotent: each successful
call increments the fence epoch.

**`renew`** -- extends the lease deadline without modifying shard progress.
The fence epoch does NOT change. Not idempotent via OpId; duplicate calls
simply extend the deadline further (harmless).

**`checkpoint`** -- persists a new cursor position (idempotent). Validates
cursor monotonicity (`new.last_key >= old.last_key` lexicographic) and
cursor bounds (`last_key` within `[spec.start, spec.end)`).

**`complete`** -- marks the shard as successfully done (terminal). Records a
final cursor, releases the lease, and transitions to `Done`.

**`park_shard`** -- halts the shard due to an error condition (terminal).
Records a `ParkReason`, releases the lease, and transitions to `Parked`.

**`split_replace`** -- replaces the parent with N child shards (terminal for
parent). Validates split coverage (children must exactly partition the
parent's key range). Children inherit `cursor_semantics` from the parent.

**`split_residual`** -- shrinks the parent and spawns a residual (non-terminal
for parent). Validates that the new parent range + residual range partition
the old range, and that the parent's cursor remains within the shrunk range.

### Safety invariants (all backends)

Every backend implementation must maintain these invariants:

- **Tenant isolation** -- a request scoped to tenant A must never read or
  write shard records belonging to tenant B.
- **Fence epoch monotonicity** -- `fence_epoch` is monotonically
  non-decreasing per shard; it increments on every ownership transfer.
- **Idempotency** -- for any operation with an OpId: same
  `(op_id, payload_hash)` returns cached result; same `op_id` with different
  hash returns `OpIdConflict`; new `op_id` executes fresh.
- **Cursor monotonicity** -- across checkpoints within the same lease epoch,
  `cursor.last_key` must be lexicographically non-decreasing.
- **Cursor bounds** -- `cursor.last_key` must fall within the shard's
  `[spec.start, spec.end)`.
- **Split coverage** -- split children must exactly partition the parent's
  key range (no gaps, no overlaps).
- **Terminal irreversibility** -- once a shard reaches Done, Split, or
  Parked, no protocol operation changes its status.

---

## 9. Cursor Semantics

The `Cursor` type is a two-layer progress marker:

```text
┌──────────────────────────────────────────────────────┐
│ last_key: Option<Box<[u8]>>                          │
│   → coordinator-visible, lex-comparable              │
│   → represents the last item key fully processed     │
├──────────────────────────────────────────────────────┤
│ token: Option<Box<[u8]>>                             │
│   → connector-opaque resume state                    │
│   → pagination cursor, continuation token, etc.      │
└──────────────────────────────────────────────────────┘
```

The `Cursor` type is the API-boundary representation used across
`CoordinationBackend` trait methods. Internally, the in-memory coordinator
stores cursor fields as `PooledCursor` — a pair of `Option<ByteSlot>` handles
into a shared `ByteSlab` — eliminating per-checkpoint heap allocations on the
hot path. The `to_cursor` / `from_cursor` methods convert between the pooled
representation and the owned `Cursor` at API boundaries.

### Monotonicity rules

| old.last_key | new.last_key             | Verdict                     |
|:------------:|:------------------------:|-----------------------------|
| `None`       | `None`                   | OK -- no-op checkpoint      |
| `None`       | `Some(k)`                | OK -- first progress        |
| `Some(a)`    | `Some(b)` where `b >= a` | OK -- forward progress      |
| `Some(a)`    | `Some(a)`                | OK -- idempotent retry      |
| `Some(_)`    | `None`                   | **REJECT** -- reset to none |
| `Some(a)`    | `Some(b)` where `b < a`  | **REJECT** -- regression    |

### CursorSemantics

A per-run configuration (`#[repr(u8)]`) that controls when cursor advancement
counts as committed progress:

- **`Completed` (0)** -- strongest guarantee. The cursor only advances after
  all work up to that point is fully processed and results are durable.
- **`Dispatched` (1)** -- weaker but higher throughput. The cursor advances
  after work is durably dispatched but not necessarily fully processed.

The coordinator enforces monotonicity and bounds identically under both
semantics.

### ShardSpec

`ShardSpec` defines a shard's key range as a half-open interval
`[start, end)` in lexicographic byte order, plus opaque connector metadata.
Empty start (`[]`) means "start of keyspace"; empty end (`[]`) means
"end of keyspace" (unbounded).

Reference: Bigtable (Chang et al., OSDI 2006), Spanner (Corbett et al.,
OSDI 2012), CockroachDB, FoundationDB (Zhou et al., SIGMOD 2021) -- all use
half-open `[start, end)` byte-key ranges.

---

## 10. Design Decisions

| ID    | Decision                                                                          |
|-------|-----------------------------------------------------------------------------------|
| D2.1  | Two-layer `(last_key, token)` cursor structure                                    |
| D2.2  | ShardSpec has half-open key range `[start, end)` with lex-ordered byte boundaries |
| D2.3  | Cursor monotonicity is a hard safety invariant                                    |
| D2.4  | Cursor bounds checking is a hard safety invariant                                 |
| D2.5  | A checkpoint requires a `last_key`                                                |
| D2.6  | ShardStatus: exactly 4 states (Active, Done, Split, Parked)                       |
| D2.7  | `park_reason.is_some()` iff `status == Parked`                                    |
| D2.8  | Payload hashes use domain-separated BLAKE3 with `CanonicalBytes`                  |
| D2.10 | Derived shard IDs have bit 63 set                                                 |
| D2.11 | ShardRecord is self-contained (no back-references to RunConfig)                   |
| D2.12 | ShardSnapshotView excludes lease, fence, op_log, tenant, park_reason               |
| D2.13 | Trait is synchronous (returns `Result`, not futures)                              |
| D2.14 | Lease-gated operations take `(TenantId, Lease)`                                   |
| D2.15 | `acquire_and_restore_into` is the only non-lease operation                             |
| D2.16 | Error types are operation-specific enums via `From<CoordError>`                   |
| D2.17 | `now: LogicalTime` passed explicitly (deterministic simulation)                   |
| D2.18 | `RunRecord` is the authoritative run record                                       |
| D2.19 | RunStatus: 5 states (Initializing, Active, Done, Failed, Cancelled)               |
| D2.20 | Two-phase creation: `create_run` then `register_shards`                           |
| D2.21 | Admin operations not lease-gated                                                  |
| D2.22 | `RunManagement` separate from `CoordinationBackend`                               |
| D2.23 | `LogicalTime` passed explicitly to all mutating operations                        |
| D2.24 | Shard listing returns `ShardSummary` (lightweight)                                |
| D2.25 | `RunRecord` has its own op-log (cap: 8)                                           |
| D2.26 | Arena-pooled byte storage via `ByteSlab` for `ShardRecord` variable-size fields   |

---

## 11. Error Architecture

### CoordError

A shared `CoordError` enum with 12 variants provides the building blocks for
all operation-specific errors. Variants cover tenant isolation, fencing, lease
expiry, terminal status, OpId conflicts, cursor violations, split validation
failures, and missing checkpoint keys.

### Operation-specific narrowing

Each operation has its own error type that wraps `CoordError` via
`From<CoordError>`. The `From` impls **explicitly enumerate** all rejected
variants (no wildcard `_` catch-all), so adding a new `CoordError` variant
triggers a compile error in every `From` impl, forcing a conscious routing
decision.

| Operation             | Error Type           | OpIdConflict? | Cursor Variants? | Split Variants? |
|-----------------------|----------------------|:-------------:|:----------------:|:---------------:|
| `acquire_and_restore_into` | `AcquireError`       | No            | No               | No              |
| `renew`               | `RenewError`         | No            | No               | No              |
| `checkpoint`          | `CheckpointError`    | Yes           | Yes              | No              |
| `complete`            | `CompleteError`      | Yes           | Yes              | No              |
| `park_shard`          | `ParkError`          | Yes           | No               | No              |
| `split_replace`       | `SplitReplaceError`  | Yes           | No               | Yes             |
| `split_residual`      | `SplitResidualError` | Yes           | No               | Yes             |

### IdempotentOutcome

The `IdempotentOutcome<T>` wrapper distinguishes first execution from replay:

```rust
pub enum IdempotentOutcome<T> {
    Executed(T),   // first execution
    Replayed(T),   // retry -- result from op-log
}
```

Callers generally do not need to distinguish -- the result is the same. The
distinction is useful for observability (metrics, logging).

### Security redaction

- **SEC-1**: `TenantMismatch` errors only expose `expected` (the caller's
  tenant), never the actual tenant -- prevents cross-tenant enumeration.
- **SEC-5**: `AlreadyLeased` error redacts `current_owner` in both `Display`
  and `Debug` to prevent worker identity leakage.
- **SEC-6**: `OpIdConflict` errors redact `expected_hash` and `actual_hash`
  in both `Display` and `Debug`.

---

## 12. In-Memory Reference Implementation

`InMemoryCoordinator` is the **executable specification** for the shard
coordination protocol. It implements both `CoordinationBackend` and
`RunManagement`.

### Key characteristics

- **Single-threaded** -- `&mut self` serializes all operations, eliminating
  concurrency concerns so invariants can be verified in-line.
- **Purely in-memory** -- two-level `AHashMap<TenantId, AHashMap<ShardKey, ShardRecord>>`.
  No I/O, no transactions, no retries.
- **Arena-pooled byte storage** -- a shared `slab: ByteSlab` owns all
  variable-size byte data (key-range start/end, metadata, cursor last-key,
  cursor token). `ShardRecord` fields hold `PooledShardSpec` and
  `PooledCursor` wrappers whose `ByteSlot` handles index into the slab.
  This replaces per-field `Box<[u8]>` heap allocations with slab operations
  on the `checkpoint` and `acquire_and_restore_into` hot paths (D2.26).
- **Tiger-style invariant enforcement** -- every mutation path calls
  `ShardRecord::assert_invariants()` before returning.

### Keying strategy

Shards use a two-level map: the outer level (`TenantId`) provides O(1) tenant
isolation -- a wrong-tenant lookup misses at the outer map without scanning
any shard records. The inner level (`ShardKey`) reduces hash input from 48
bytes (composite key) to 16 bytes. A `total_shard_count` is maintained inline
for O(1) global limit checks.

### Shard count limits

The coordinator enforces per-tenant and global shard count limits to prevent
split-flooding (CWE-400). `check_shard_limits` runs before every split and
shard registration, accounting for temporarily-removed records in the
remove-mutate-restore pattern.

---

## 13. References

- Gray, C. and Cheriton, D. "Leases: An Efficient Fault-Tolerant Mechanism
  for Distributed File Cache Consistency." SOSP 1989.
- Kleppmann, M. "How to do distributed locking." 2016.
  https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html
- Zhou, J. et al. "FoundationDB: A Distributed Unbundled Transactional Key
  Value Store." SIGMOD 2021.
- Stripe. "Designing robust and predictable APIs with idempotency."
  (Brandur Leach, 2017).
- Bacon, D. et al. "Spanner: Becoming a SQL System." SIGMOD 2017.
- TigerBeetle. VOPR (Viewstamped Operation Replayer) deterministic
  simulation.
- Lamport, L. *Specifying Systems: The TLA+ Language and Tools for Hardware
  and Software Engineers.* Addison-Wesley, 2002.
- Newcombe, C. et al. "How Amazon Web Services Uses Formal Methods."
  Communications of the ACM 58(4), April 2015.
