# Phase 2: Boundary ② Normative Specification & Implementation Plan

> **Purpose**: Define the operational semantics of every B2 coordination operation
> as state transitions with explicit preconditions, postconditions, and atomicity
> requirements. Then decompose implementation into bite-sized steps.
>
> **Audience**: The implementor (you). This document is the bridge between the
> B2 contract types (already drafted) and the in-memory backend implementation.
>
> **Status**: DRAFT — ready for review before implementation begins.

---

## Part I: Normative Specification

### §1 State Model

The coordinator manages two kinds of stateful records: **ShardRecord** and **RunRecord**.
Each is keyed and scoped to a tenant. The coordinator never reads a clock — `now: LogicalTime`
is an explicit input to every operation.

**Reference**: FoundationDB simulation — time as input, not observation
(Zhou et al., SIGMOD 2021); Scanner Instructions §9 Anti-Pattern #5.

#### §1.1 Shard State Machine

A shard has exactly four states. Transitions from `Active` are the only protocol
transitions. `Done`, `Split`, and `Parked` are terminal within the protocol.

```
                   ┌──────────────┐
           ┌──────►│    Active    │◄──────┐
           │       └──┬───┬───┬──┘       │
           │          │   │   │          │
           │ complete │   │   │ park     │
           │   ┌──────┘   │   └──────┐   │
           │   ▼   split  │         ▼   │
           │ ┌──────┐ replace ┌────────┐ │
           │ │ Done │    │    │ Parked │ │
           │ └──────┘    ▼    └────────┘ │
           │        ┌────────┐           │
           │        │ Split  │           │
           │        └────────┘           │
           │                             │
           └──── unpark (admin, ─────────┘
                  out-of-band,
                  bumps fence)
```

State transition table (protocol operations only):

| Current   | Operation        | Next     | Fence Δ | Lease Released? |
|-----------|-----------------|----------|---------|-----------------|
| Active    | complete         | Done     | +0      | Yes             |
| Active    | park_shard       | Parked   | +0      | Yes             |
| Active    | split_replace    | Split    | +0      | Yes             |
| Active    | split_residual   | Active*  | +0      | No (stays)      |
| Active    | checkpoint       | Active   | +0      | No              |
| Active    | renew            | Active   | +0      | No (extends)    |
| Any       | acquire_and_restore | Active | +1   | N/A (grants)    |
| Parked    | unpark (admin)   | Active   | +1      | N/A (clears)    |

*split_residual shrinks the parent's spec but keeps it Active.

**Safety invariant (terminal irreversibility)**: Once `status ∈ {Done, Split, Parked}`,
no protocol operation changes status. Source: D2.6, INV-S06.

**Safety invariant (fence monotonicity)**: `fence_epoch` is monotonically non-decreasing
per shard. It increments exactly once on each ownership transfer (`acquire_and_restore`,
`unpark`). Source: D2.14, INV-S02.

#### §1.2 Run State Machine

```
  ┌──────────────┐
  │ Initializing │──── register_shards ────┐
  └──────┬───────┘                         │
         │ (timeout / cancel)              │
         ▼                                 ▼
    ┌─────────┐                      ┌──────────┐
    │ Failed  │                      │  Active  │
    └─────────┘                      └────┬─────┘
                                          │
                          ┌───────────────┼───────────────┐
                    all shards Done  any Parked        cancel
                          │               │               │
                          ▼               ▼               ▼
                     ┌────────┐     ┌─────────┐     ┌─────────┐
                     │  Done  │     │ Failed  │     │ Failed  │
                     └────────┘     └─────────┘     └─────────┘
```

Run terminal status is evaluated externally — the coordinator does not auto-compute it.
Source: D2.19.

#### §1.3 The Fencing Protocol

The core safety property: **zombies can run, but zombies must not be able to commit**.

A "zombie" is a worker holding a stale lease — its `fence_epoch` is behind the shard
record's current epoch because another worker has since acquired the shard.

The protocol, in Kleppmann's framing:

1. **acquire_and_restore** increments `fence_epoch` and returns a `Lease` containing the new epoch.
2. Every subsequent mutation (checkpoint, complete, park, split) carries the `Lease`.
3. The backend validates `lease.fence == record.fence_epoch` before executing.
4. If `lease.fence < record.fence_epoch` → `StaleFence` error. The zombie is rejected.

**Why this is safe**: The fence epoch is monotonic and stored durably. Even if a
zombie worker's network partition heals after a new worker has acquired the shard,
the zombie's writes carry the old epoch and are rejected. The zombie may have done
work (scanning files, detecting secrets), but it cannot commit that work to
coordination state.

**Reference**: Kleppmann, "How to do distributed locking" (2016);
Gray & Cheriton, "Leases" (SOSP 1989);
Hochstein, "Locks, Leases, Fencing Tokens, FizzBee!" (2025).

#### §1.4 The Idempotency Protocol

Every mutating operation (except `acquire_and_restore` and `renew`) accepts an `OpId`.
The backend maintains a bounded op-log per shard record (cap: 16 entries, FIFO eviction).

Decision procedure for `(op_id, payload_hash)`:

```
match record.op_log_lookup(op_id):
  None                        → new operation, execute and record
  Some(entry) where entry.payload_hash == payload_hash
                              → replay, return cached result (Replayed)
  Some(entry) where entry.payload_hash != payload_hash
                              → conflict error (OpIdConflict)
```

The `payload_hash` is a non-cryptographic fingerprint of the operation's semantic
content (e.g., `hash_checkpoint_payload(new_cursor)`). It guards against accidental
reuse of an `OpId` with different inputs — a client bug.

**Reference**: Stripe idempotency key pattern (Brandur Leach, 2017);
IETF Draft: Idempotency-Key HTTP Header Field.

---

### §2 Operation Specifications

Each operation is specified as:
- **Signature** (from the trait)
- **Preconditions** (what must be true before execution)
- **Steps** (the state transition, in order)
- **Postconditions** (what is guaranteed after successful return)
- **Error conditions** (what causes rejection)
- **Atomicity** (what must be atomic)

#### §2.1 `acquire_and_restore`

**Signature**:
```rust
fn acquire_and_restore(
    &mut self, now: LogicalTime, tenant: TenantId,
    key: ShardKey, worker: WorkerId,
) -> Result<AcquireResult, AcquireError>;
```

**Preconditions**: The shard record exists, belongs to `tenant`, and is `Active`.

**Steps** (atomic):
1. Look up `record` by `(tenant, key)`.
2. Assert `record.tenant == tenant` → else `TenantMismatch`.
3. Assert `record.status == Active` → else `ShardTerminal`.
4. If `record.is_leased_at(now)` (lease not expired) → `AlreadyLeased`.
5. `record.fence_epoch += 1`.
6. `record.lease_owner = Some(worker)`.
7. `record.lease_deadline = Some(now + lease_duration)`.
8. Build `Lease { tenant, run: key.run, shard: key.shard, owner: worker, fence: record.fence_epoch, deadline: record.lease_deadline.unwrap() }`.
9. Build `ShardSnapshot { spec, cursor, cursor_semantics, parent, spawned }` from record.
10. Return `AcquireResult { lease, snapshot }`.

**Postconditions**:
- `record.fence_epoch == old_fence_epoch + 1`
- `record.lease_owner == Some(worker)`
- `record.lease_deadline > now`
- Any previous worker's lease is invalidated (their epoch < new epoch).

**Not idempotent**: Each successful call increments the fence. Two calls = two epochs.
Source: D2.15.

**Atomicity**: Steps 5–7 must be atomic with respect to concurrent operations on the same shard.

#### §2.2 `renew`

**Signature**:
```rust
fn renew(
    &mut self, now: LogicalTime, tenant: TenantId, lease: &Lease,
) -> Result<RenewResult, RenewError>;
```

**Preconditions**: Valid lease (tenant match, fence match, not expired, shard Active).

**Steps** (atomic):
1. Look up `record` by `(tenant, ShardKey { run: lease.run, shard: lease.shard })`.
2. `validate_lease(now, tenant, lease, record)?`.
3. `record.lease_deadline = Some(now + lease_duration)`.
4. Return `RenewResult { new_deadline: record.lease_deadline.unwrap() }`.

**Postconditions**:
- `record.fence_epoch` unchanged.
- `record.lease_owner` unchanged.
- `record.lease_deadline > now`.

**Not idempotent via OpId**: Renewal is a timing operation, not a semantic one.
Multiple renewals are harmless — each just extends the deadline.

#### §2.3 `checkpoint`

**Signature**:
```rust
fn checkpoint(
    &mut self, now: LogicalTime, tenant: TenantId, lease: &Lease,
    new_cursor: Cursor, op_id: OpId,
) -> Result<IdempotentOutcome<()>, CheckpointError>;
```

**Preconditions**: Valid lease; `new_cursor.last_key.is_some()`;
`new_cursor.last_key >= record.cursor.last_key` (lex);
`new_cursor.last_key ∈ [spec.start, spec.end)`.

**Steps** (atomic):
1. Look up `record` by `(tenant, ShardKey from lease)`.
2. `validate_lease(now, tenant, lease, record)?`.
3. Compute `payload_hash = hash_checkpoint_payload(&new_cursor)`.
4. `check_op_idempotency(record, op_id, payload_hash)?`:
   - `Some(entry)` → return `Replayed(())`.
   - `None` → continue to step 5.
5. `validate_cursor_update(&new_cursor, record)?`.
6. `record.cursor = new_cursor`.
7. Push `OpLogEntry { op_id, kind: Checkpoint, result: Completed, payload_hash, executed_at: now }` to `record.op_log` (FIFO evict if at cap).
8. Return `Executed(())`.

**Postconditions**:
- `record.cursor.last_key >= old_cursor.last_key`.
- Op-log contains entry for `op_id`.
- `record.status` unchanged (`Active`).

**Idempotent**: Same `(op_id, payload_hash)` → `Replayed(())`. Same `op_id`, different hash → `OpIdConflict`.

#### §2.4 `complete`

**Signature**:
```rust
fn complete(
    &mut self, now: LogicalTime, tenant: TenantId, lease: &Lease,
    final_cursor: Cursor, op_id: OpId,
) -> Result<IdempotentOutcome<()>, CompleteError>;
```

**Preconditions**: Valid lease; cursor constraints (same as checkpoint).

**Steps** (atomic):
1. Look up record. `validate_lease`. Compute `hash_complete_payload`.
2. `check_op_idempotency`:
   - Replay → `Replayed(())`.
   - New → continue.
3. `validate_cursor_update(&final_cursor, record)?`.
4. `record.cursor = final_cursor`.
5. `record.status = Done`.
6. `record.lease_owner = None`.
7. `record.lease_deadline = None`.
8. Push op-log entry (kind: `Complete`, result: `Completed`).
9. Return `Executed(())`.

**Postconditions**:
- `record.status == Done` (terminal).
- Lease released.
- No further mutations accepted.

#### §2.5 `park_shard`

**Signature**:
```rust
fn park_shard(
    &mut self, now: LogicalTime, tenant: TenantId, lease: &Lease,
    reason: ParkReason, op_id: OpId,
) -> Result<IdempotentOutcome<()>, ParkError>;
```

**Steps** (atomic):
1. Validate lease. Compute `hash_park_payload(reason)`. Check idempotency.
2. `record.status = Parked`.
3. `record.park_reason = Some(reason)`.
4. `record.lease_owner = None`.
5. `record.lease_deadline = None`.
6. Push op-log entry.
7. Return `Executed(())`.

**Postconditions**:
- `record.status == Parked`, `record.park_reason.is_some()`.
- Invariant D2.7: `park_reason.is_some() iff status == Parked`.

#### §2.6 `split_replace`

**Signature**:
```rust
fn split_replace(
    &mut self, now: LogicalTime, tenant: TenantId, lease: &Lease,
    plan: SplitReplacePlan, op_id: OpId,
) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError>;
```

**Steps** (atomic):
1. Validate lease. Compute `hash_split_replace_payload(&plan)`. Check idempotency.
   - On replay: return `Replayed(SplitReplaceResult { children: <cached child IDs> })`.
2. `validate_split_coverage(&record.spec, &plan.children_specs)?` → `SplitInvalid` on failure.
3. For each child `i` in `0..plan.children_specs.len()`:
   a. `child_id = derive_split_shard_id(record.shard, DerivedShardKind::Child, i as u32)`.
   b. Create `ShardRecord` for child:
      - `tenant: record.tenant`, `run: record.run`, `shard: child_id`
      - `status: Active`, `spec: plan.children_specs[i]`
      - `cursor: plan.children_cursors[i]` (or `Cursor::initial()`)
      - `cursor_semantics: record.cursor_semantics`
      - `fence_epoch: FenceEpoch::INITIAL`, `parent: Some(record.shard)`
   c. Insert child record into store.
4. `record.status = Split`.
5. `record.spawned.extend(child_ids)`.
6. `record.lease_owner = None`, `record.lease_deadline = None`.
7. Push op-log entry.
8. Return `Executed(SplitReplaceResult { children: child_ids })`.

**Postconditions**:
- Parent `status == Split` (terminal).
- N child records exist, all `Active`, collectively covering parent's range.
- Child IDs are deterministic — same inputs → same IDs (idempotent splits).

**Reference**: D2.9 (split validation), D2.10 (deterministic child IDs).

#### §2.7 `split_residual`

**Signature**:
```rust
fn split_residual(
    &mut self, now: LogicalTime, tenant: TenantId, lease: &Lease,
    plan: SplitResidualPlan, op_id: OpId,
) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError>;
```

**Steps** (atomic):
1. Validate lease. Compute hash. Check idempotency.
2. `validate_residual_split(&record.spec, &plan.parent_new_spec, &plan.residual_spec)?`.
3. `residual_id = derive_split_shard_id(record.shard, DerivedShardKind::Residual, 0)`.
4. Create residual `ShardRecord` (Active, initial cursor, `parent: Some(record.shard)`).
5. `record.spec = plan.parent_new_spec` (shrink parent).
6. `record.spawned.push(residual_id)`.
7. Parent keeps its lease (no release — it continues scanning).
8. Push op-log entry.
9. Return `Executed(SplitResidualResult { residual: residual_id })`.

**Postconditions**:
- Parent still `Active` with smaller spec.
- Residual is a new `Active` shard covering `[split_point, old_end)`.
- Parent retains its lease.

---

### §3 Run-Level Operation Specifications

#### §3.1 `create_run`

**Preconditions**: Run with this `RunId` does not already exist for `tenant`.

**Steps**:
1. Create `RunRecord { tenant, run, config, status: Initializing, created_at: now, shards: vec![] }`.
2. Push run op-log entry.
3. Return run record.

#### §3.2 `register_shards`

**Preconditions**: Run exists, `status == Initializing`.

**Steps** (atomic):
1. `validate_manifest(&initial_shards)?` — no duplicates, no overlaps, valid specs.
2. For each `InitialShard`: create `ShardRecord` (Active, initial fence, initial cursor).
3. `run.shard_manifest = shard_ids`.
4. `run.status = Active`.
5. Push run op-log entry.

#### §3.3 `complete_run`, `fail_run`, `cancel_run`

These transition the run to terminal states (`Done` or `Failed`). All are
idempotent via `OpId`. All require `run.status == Active` (except `cancel_run`
which can also cancel `Initializing` runs).

#### §3.4 Admin: `unpark_shard`

**Preconditions**: Shard exists, `status == Parked`. NOT lease-gated (admin operation).

**Steps**:
1. `record.status = Active`.
2. `record.park_reason = None`.
3. `record.fence_epoch += 1` (invalidates any lingering references).
4. `record.lease_owner = None`, `record.lease_deadline = None`.
5. Push op-log entry.

**Reference**: D2.6, D2.21 — unpark is out-of-band, bumps fence.

---

### §4 Validation Helper Specifications

These are pure functions already defined in B2C3. The in-memory backend calls
them as the reusable preamble for each operation.

#### §4.1 `validate_lease(now, tenant, lease, record) -> Result<(), CoordError>`

Check order (most actionable error first):
1. `record.tenant == tenant` → else `TenantMismatch`
2. `!record.status.is_terminal()` → else `ShardTerminal`
3. `lease.fence == record.fence_epoch` → else `StaleFence`
4. `record.is_leased_at(now)` → else `LeaseExpired`

#### §4.2 `validate_cursor_update(new_cursor, record) -> Result<(), CoordError>`

1. `new_cursor.last_key.is_some()` → else `CheckpointMissingKey`
2. `check_cursor_advance(&record.cursor, new_cursor) == Forward` → else `CursorRegression`
3. `check_cursor_bounds(new_cursor, &record.spec) == InBounds` → else `CursorOutOfBounds`

#### §4.3 `check_op_idempotency(record, op_id, payload_hash) -> Result<Option<&OpLogEntry>, CoordError>`

1. `record.op_log_lookup(op_id)`:
   - `None` → `Ok(None)` (new op)
   - `Some(e)` where `e.payload_hash == payload_hash` → `Ok(Some(e))` (replay)
   - `Some(e)` where `e.payload_hash != payload_hash` → `Err(OpIdConflict)`

---

### §5 Invariant Catalog (Cross-Referenced)

Every invariant below is tagged with its source design decision and the
implementation step where it must be enforced.

| ID      | Kind   | Invariant                                         | Source | Impl Step |
|---------|--------|---------------------------------------------------|--------|-----------|
| INV-S01 | Safety | Tenant isolation on every operation               | D2.14  | Step 2    |
| INV-S02 | Safety | Fence epoch monotonically non-decreasing          | D2.14  | Step 3    |
| INV-S03 | Safety | Stale fence rejected                              | D2.14  | Step 2    |
| INV-S04 | Safety | Expired lease rejected                            | D2.14  | Step 2    |
| INV-S05 | Safety | Cursor monotonicity (last_key non-decreasing)     | D2.3   | Step 4    |
| INV-S06 | Safety | Terminal irreversibility                           | D2.6   | Step 3    |
| INV-S07 | Safety | park_reason.is_some() iff status == Parked         | D2.7   | Step 3    |
| INV-S08 | Safety | Op-log bounded (≤16 entries per shard, ≤4 per run) | D2.8   | Step 4    |
| INV-S09 | Safety | Split coverage: children exactly partition parent  | D2.9   | Step 5    |
| INV-S10 | Safety | Deterministic child IDs from split                | D2.10  | Step 5    |
| INV-S11 | Safety | Idempotent replay returns same result              | D2.8   | Step 4    |
| INV-S12 | Safety | OpId conflict detected and rejected                | D2.8   | Step 4    |
| INV-S13 | Safety | Cursor bounds within shard spec                   | D2.4   | Step 4    |
| INV-L01 | Liveness | Lease expires if not renewed                     | D2.14  | Step 3    |
| INV-L02 | Liveness | Every shard eventually reaches terminal state    | D2.6   | N/A (runtime) |

---

### §6 TLA+ Focus Areas

Before implementation, a focused TLA+ spec should cover the two Tier 1 safety properties:

**Property 1 — Mutual exclusion via fencing**:
At most one worker may successfully execute fenced mutations on a shard at any point
in the (logical) execution. Formally: if two workers both hold a `Lease` for the same
shard, at most one has `lease.fence == record.fence_epoch`.

**Property 2 — Zombie commit rejection**:
If worker W₁ acquired at epoch E and worker W₂ subsequently acquired at epoch E+1,
then any mutation by W₁ carrying epoch E is rejected after W₂'s acquisition.

These two properties capture the essential safety of the coordination protocol.
The TLA+ spec models: N workers, 1 shard, acquire/checkpoint/complete operations,
with non-deterministic crash and recovery between any two steps.

**Reference**: Newcombe et al., "How Amazon Web Services Uses Formal Methods" (CACM 2015);
Hochstein, "Locks, Leases, Fencing Tokens, FizzBee!" (2025).

---

## Part II: Implementation Plan

### Overview

We decompose the B2 implementation into 7 steps. Each step is self-contained,
compiles, and adds a well-defined piece of functionality. Steps 1–5 build the
in-memory coordination backend. Step 6 adds the run-level management. Step 7
adds the ergonomic wrappers and facade trait.

The order follows the dependency graph:
```
Step 1: Value types (Cursor, ShardSpec, validation functions)
  └► Step 2: Shard record types (ShardStatus, ShardRecord, Lease, OpLog)
       └► Step 3: Error types and validation helpers
            └► Step 4: CoordinationBackend trait + InMemoryCoordinator (shard ops)
                 └► Step 5: Split operations (split_replace, split_residual)
                      └► Step 6: Run-level types + RunManagement trait + impl
                           └► Step 7: WorkerSession, ShardClaiming, CoordinationFacade
```

### Step 1: Value Types — Cursor, ShardSpec, Validation Functions

**What we build**: The types from B2C1 — `Cursor`, `ShardSpec`, `CursorAdvance`,
`CursorBoundsCheck`, `CursorSemantics`, `SplitValidationError`, plus the pure
validation functions (`check_cursor_advance`, `check_cursor_bounds`,
`validate_split_coverage`, `validate_residual_split`).

**Why first**: Every other B2 type depends on `Cursor` and `ShardSpec`. The
validation functions are pure — no state, no backend — so they're the easiest
to get right and the most amenable to property-based testing.

**What to implement** (from B2C1 draft):

- `Cursor` struct with `initial()`, `with_last_key()`, `from_parts()`, `is_initial()`.
  `CanonicalBytes` impl using presence-byte encoding for `Option` fields.
- `CursorSemantics` enum (`Completed`, `Dispatched`) with `from_u8`/`as_u8`.
  `CanonicalBytes` impl.
- `ShardSpec` struct with `with_range()`, `with_range_and_metadata()`,
  `contains_key()`, `is_valid()`. `CanonicalBytes` impl.
- `CursorAdvance` enum and `check_cursor_advance(old, new)` function.
  Logic: compare `last_key` fields lexicographically, handle `None` cases
  per the monotonicity table in the Cursor doc comment.
- `CursorBoundsCheck` enum and `check_cursor_bounds(cursor, spec)` function.
  Logic: `last_key ∈ [spec.start, spec.end)` with lex comparison.
- `SplitValidationError` enum.
- `validate_split_coverage(parent, children)` — checks start alignment, end
  alignment, contiguous coverage, no gaps, at least 2 children.
- `validate_residual_split(old, new_parent, residual)` — checks start alignment,
  end alignment, junction point.

**Key learning**: The cursor monotonicity rules are the first line of defense
against data corruption. Study the monotonicity table in B2C1 carefully — the
`None → Some`, `Some → Some`, `Some → None` cases map directly to the operational
semantics of "first progress", "forward progress", and "regression" respectively.

**Potential issues to watch**:
- The `CanonicalBytes` impl for `Option<Box<[u8]>>` must use presence-byte encoding
  (0x00 for None, 0x01 + length + data for Some) to ensure `None` and `Some(empty)`
  hash differently. The B2C1 draft has a test for this — make sure it passes.
- `validate_split_coverage` must sort children by start key before checking
  contiguity. The caller may provide children in any order.

---

### Step 2: Shard Lifecycle Types — ShardStatus, ShardRecord, Lease, OpLog

**What we build**: The types from B2C2 — `ShardStatus`, `ParkReason`, `ShardRecord`,
`ShardSnapshot`, `Lease`, `OpLogEntry`, `OpKind`, `OpResult`, `SplitReplacePlan`,
`SplitReplaceResult`, `SplitResidualPlan`, `SplitResidualResult`, and the payload
hash functions.

**Why second**: `ShardRecord` is the central data structure of the coordination layer.
It contains `Cursor`, `ShardSpec`, `Lease` fields, `OpLog` — all from Step 1 and this step.
The in-memory backend (Step 4) is essentially a `HashMap<ShardKey, ShardRecord>`.

**What to implement** (from B2C2 draft):

- `ShardStatus` enum (4 variants, `#[repr(u8)]`) with `is_terminal()`, `from_u8`.
- `ParkReason` enum with `from_u8`/`as_u8`, `CanonicalBytes`.
- `OpKind` enum (Checkpoint, Complete, Park, SplitReplace, SplitResidual).
- `OpResult` enum (Completed, Error, Superseded).
- `OpLogEntry` struct (`op_id`, `kind`, `result`, `payload_hash`, `executed_at`).
- `ShardRecord` struct — the big one. All fields from the draft.
  - `assert_invariants(&self)` method: validates park_reason consistency,
    lease consistency, terminal-implies-no-lease, fence minimum, op-log bounded.
  - `is_leased_at(now: LogicalTime) -> bool`: checks `lease_deadline > now`.
  - `op_log_lookup(op_id: OpId) -> Option<&OpLogEntry>`: linear scan (bounded, ≤16).
  - `push_op_log(entry: OpLogEntry)`: push, evict oldest if at cap.
- `ShardSnapshot` struct (D2.12 — excludes lease, fence, op_log, tenant).
- `Lease` struct (already in B1C2, but fully defined here with all fields).
- `SplitReplacePlan`, `SplitReplaceResult`, `SplitResidualPlan`, `SplitResidualResult`.
- `derive_split_shard_id(parent, kind, index)` — deterministic child ID derivation
  using `domain_hasher(domain::SPLIT_ID_V1)` and `finalize_64` with bit 63 set.
- Payload hash functions: `hash_checkpoint_payload`, `hash_complete_payload`,
  `hash_park_payload`, `hash_split_replace_payload`, `hash_split_residual_payload`.

**Key learning**: The `ShardRecord.assert_invariants()` method is Tiger Style in action.
Every method that mutates a `ShardRecord` should call `assert_invariants()` at exit.
This catches contract violations at the mutation site rather than downstream.

**Potential issues to watch**:
- `derive_split_shard_id` sets bit 63 on the raw u64 to distinguish derived IDs
  from root IDs. The B2C2 draft uses `finalize_64` on a domain-tagged hash, then
  ORs with `1 << 63`. Make sure this doesn't collide with how `ShardId` handles
  display/debug formatting.
- The op-log cap (16 entries) with FIFO eviction means old entries are lost.
  This is intentional — the op-log is a replay cache, not a full audit log.
  But it means idempotency guarantees have a time window: if a worker retries
  after 16+ other operations on the same shard, the replay entry is gone and
  the operation may be re-executed. This is acceptable because the operations
  themselves are designed to be safe to re-execute (cursor advances are
  monotonic, terminal transitions are no-ops on terminal shards).

---

### Step 3: Error Types and Validation Helpers

**What we build**: The types from B2C3 §3.1–§3.7 — `CoordError`, all operation-specific
error types (`AcquireError`, `RenewError`, `CheckpointError`, `CompleteError`, `ParkError`,
`SplitReplaceError`, `SplitResidualError`), the `From<CoordError>` impls, and the
validation helper functions (`validate_lease`, `validate_cursor_update`, `check_op_idempotency`).

**Why third**: The trait definition (Step 4) uses these types in its signatures.
The validation helpers are the reusable preamble that every operation calls.
Implementing them separately lets us test the validation logic in isolation
before it's wired into the backend.

**What to implement** (from B2C3 draft):

- `CoordError` enum — 10 variants covering all failure modes.
- 7 operation-specific error types, each wrapping relevant `CoordError` variants.
- `From<CoordError>` impls for each operation error type.
  These use `unreachable!()` for invalid conversions — a logic bug if hit.
- `AcquireResult`, `RenewResult` structs.
- `IdempotentOutcome<T>` enum with `into_inner()`, `is_replay()`, `map()`.
- `validate_lease(now, tenant, lease, record)` — the four-check preamble.
- `validate_cursor_update(new_cursor, record)` — non-empty key + monotonicity + bounds.
- `check_op_idempotency(record, op_id, payload_hash)` — op-log lookup with conflict detection.

**Key learning**: The error type design follows the principle of operation-specific
newtypes over a shared enum (D2.16). This is a deliberate tradeoff: callers get
precise error matching (e.g., `CheckpointError` can't produce `AlreadyLeased`),
but we pay with boilerplate `From` impls. The boilerplate is finite and mechanical.

The `validate_lease` check order (tenant → terminal → fence → expiry) is specified
in the normative spec above. The order matters for error reporting — a tenant
mismatch is always a bug (highest priority), while a lease expiry is an operational
timing issue (lowest priority among the four checks).

**Potential issues to watch**:
- The `From<CoordError>` impls use `unreachable!()` for variants that shouldn't
  appear. If we ever add a new `CoordError` variant, we need to update ALL the
  `From` impls. This is fragile — consider adding a `#[non_exhaustive]` attribute
  to `CoordError` if we anticipate future variants.

---

### Step 4: CoordinationBackend Trait + InMemoryCoordinator (Core Shard Ops)

**What we build**: The `CoordinationBackend` trait definition (from B2C3) and the
first-pass in-memory implementation covering `acquire_and_restore`, `renew`,
`checkpoint`, `complete`, and `park_shard`. Split operations are deferred to Step 5.

**Why fourth**: This is the heart of the coordination layer. The trait defines
the semantic contract; the in-memory implementation proves the contract is
implementable and serves as the reference implementation for all other backends.

**What to implement**:

The trait definition itself (from B2C3 §3.6) — copy the signatures and doc comments.

The `InMemoryCoordinator` struct:
```rust
pub struct InMemoryCoordinator {
    shards: HashMap<(TenantId, ShardKey), ShardRecord>,
    runs: HashMap<(TenantId, RunId), RunRecord>,
    // lease_duration could be stored per-run via RunConfig,
    // but for the in-memory impl a global default is fine.
    default_lease_duration: u64,
}
```

**Implementation pattern for each operation** (the "fenced mutation template"):

```
fn operation(&mut self, now, tenant, lease, ..., op_id) -> Result<...> {
    // 1. Lookup
    let record = self.shards.get_mut(&(tenant, shard_key))
        .ok_or(Error::ShardNotFound { .. })?;

    // 2. Validate lease (for lease-gated ops)
    validate_lease(now, tenant, lease, record)?;   // via From<CoordError>

    // 3. Check idempotency (for OpId-carrying ops)
    let payload_hash = hash_X_payload(...);
    if let Some(_entry) = check_op_idempotency(record, op_id, payload_hash)? {
        return Ok(IdempotentOutcome::Replayed(...));
    }

    // 4. Operation-specific validation (cursor, split, etc.)
    validate_cursor_update(...)?;  // or validate_split_coverage, etc.

    // 5. Mutate record
    record.cursor = new_cursor;    // etc.

    // 6. Push op-log entry
    record.push_op_log(OpLogEntry { ... });

    // 7. Assert invariants (Tiger Style)
    record.assert_invariants();

    // 8. Return
    Ok(IdempotentOutcome::Executed(...))
}
```

This template is the direct translation of the normative spec's operation steps
into Rust. Every operation follows the same shape; the differences are in step 4
(validation) and step 5 (mutation).

**Key learning**: The `validate_lease` → `check_op_idempotency` → `validate_X` →
`mutate` → `push_op_log` → `assert_invariants` sequence is the fixed protocol
that every fenced mutation follows. Internalizing this sequence is the single
most important thing for understanding the coordination layer.

**Potential issues to watch**:
- The `HashMap` lookup uses `(TenantId, ShardKey)` as the key. `ShardKey` contains
  `RunId` which contains `JobId + PolicyHash`. Make sure `Hash` is derived/implemented
  for all of these. The B1 types already derive `Hash` — verify this.
- For `acquire_and_restore`, the "is currently leased" check uses `record.is_leased_at(now)`.
  A lease that has expired at `now` allows re-acquisition even without the old worker
  explicitly releasing it. This is the lease expiry mechanism — the coordinator doesn't
  need the old worker's cooperation.
- The in-memory implementation is single-threaded (no `Mutex`, no `Arc`). This is
  correct for the deterministic simulator and test suite. Production backends handle
  concurrency at the storage layer (transactions, CAS operations).

---

### Step 5: Split Operations

**What we build**: The `split_replace` and `split_residual` implementations in
`InMemoryCoordinator`, plus any helper types needed for split child creation.

**Why fifth**: Splits are the most complex operations — they create new shard records,
validate coverage invariants, derive deterministic IDs, and (for `split_replace`)
transition the parent to terminal. They depend on everything from Steps 1–4.

**What to implement**:

`split_replace`:
- Follow the fenced mutation template.
- After lease and idempotency validation:
  - Extract child specs from `SplitReplacePlan`.
  - Call `validate_split_coverage(&record.spec, &plan.children_specs)`.
  - For each child index, call `derive_split_shard_id` to get deterministic ID.
  - Create child `ShardRecord`s with `status: Active`, `cursor: initial()` (or from plan),
    `cursor_semantics: record.cursor_semantics`, `parent: Some(record.shard)`.
  - Insert children into `self.shards`.
  - Set parent `status = Split`, release lease, push op-log.
- For idempotent replay: re-derive child IDs (deterministic) and return them.

`split_residual`:
- Similar template but non-terminal for parent.
- Derive residual ID, create residual record, shrink parent spec.
- Parent keeps its lease (this is the key difference from `split_replace`).

**Key learning**: The deterministic ID derivation (`derive_split_shard_id`) is what
makes split idempotency possible without storing the child IDs in the op-log entry.
On replay, we re-derive the same IDs from the same inputs. This is the content-addressed
identity principle from B1 applied to coordination operations.

**Potential issues to watch**:
- When creating child records during `split_replace`, the children must be inserted
  atomically with the parent's terminal transition. In the in-memory impl, this is
  trivial (single-threaded, same HashMap). In a real backend, this requires a transaction.
- For `split_residual` idempotent replay: we need to check if the residual shard
  already exists (from a previous successful execution). If it does, return the
  existing ID. The deterministic derivation means we can check for existence by ID.

---

### Step 6: Run-Level Types + RunManagement Trait + Implementation

**What we build**: The types from B2C4 (`RunStatus`, `RunConfig` expanded,
`RunRecord`, `InitialShard`, `ShardSummary`, `ShardFilter`, `ManifestValidationError`,
`validate_manifest`), the run-level error types, the `RunManagement` trait, and the
in-memory implementation.

**Why sixth**: Run-level operations are the outer coordination layer. They depend on
shard-level operations (e.g., `register_shards` creates `ShardRecord`s) but are
simpler — the state machine has fewer states and the fencing protocol doesn't apply
(runs don't have leases).

**What to implement** (from B2C4 draft):

- `RunStatus` enum (4 states, `#[repr(u8)]`), `RunConfig`, `RunRecord`.
- `InitialShard` struct (shard_id, spec, cursor).
- `ShardSummary` (lightweight view of a shard for listing/admin).
- `ShardFilter` (declarative filtering for `list_shards`).
- `validate_manifest(&[InitialShard])` — no duplicates, no overlaps, valid specs.
- `ManifestValidationError` enum.
- Run-level error types (`CreateRunError`, `RegisterShardsError`, etc.).
- `RunManagement` trait with `create_run`, `register_shards`, `complete_run`,
  `fail_run`, `cancel_run`, `list_shards`, `get_run_status`.
- Admin operations: `unpark_shard`, `cancel_run`.
- In-memory implementations for all of the above.

**Key learning**: The two-phase run creation (`create_run` → `register_shards`) exists
because some backends can't atomically create a run and all its shards in one operation.
The in-memory backend can do it in one HashMap operation, but the two-phase API
keeps the contract honest about what production backends need.

`validate_manifest` is the scan-completeness verification entry point (Scanner
Instructions §5.3). It ensures the initial shard set has no duplicate IDs and
no overlapping key ranges. Gaps are allowed — some key ranges may be intentionally
excluded from a scan.

**Potential issues to watch**:
- `RunRecord` has its own op-log (B2C5, cap: 4 entries). The run-level op-log
  mirrors the shard op-log pattern but is smaller because run-level operations
  are infrequent.
- `ShardFilter.matches(&ShardSummary)` needs to handle the composite filter logic
  correctly: all conditions must match (AND semantics). The B2C4 draft's tests
  cover the key cases.

---

### Step 7: WorkerSession, ShardClaiming, CoordinationFacade

**What we build**: The types from B2C5 — `WorkerSession<'b, B>`, the `ShardClaiming`
trait with `claim_next_available`, `StateTransitionEvent`, the `CoordinationFacade`
super-trait, and the run-level op-log amendment.

**Why last**: These are ergonomic wrappers and composition layers. `WorkerSession`
binds a backend + tenant + worker + lease into a convenient handle. `ShardClaiming`
composes `list_shards` + `acquire_and_restore`. `CoordinationFacade` is just a
super-trait alias. None of these add new semantic capabilities — they compose
what's already built.

**What to implement** (from B2C5 draft):

- `RunOpKind` enum (for run-level op-log entries).
- Run-level op-log amendment to `RunRecord` (push, lookup, cap).
- `WorkerSession<'b, B: CoordinationBackend>` — non-owning wrapper.
  Methods: `acquire()` (static constructor), `renew()`, `checkpoint()`,
  `complete()`, `park()`, `lease()`, `snapshot()`, `shard_key()`.
- `ShardClaiming` trait with `claim_next_available` default impl.
  Composes: `list_shards(filter: available)` → try `acquire_and_restore` on each.
- `StateTransitionEvent` enum — value type returned alongside operation results.
  Events are NOT callbacks — the caller decides what to do with them.
- `CoordinationFacade` super-trait: `CoordinationBackend + RunManagement + ShardClaiming`.
- Blanket impl: `impl<T: CoordinationBackend + RunManagement + ShardClaiming> CoordinationFacade for T {}`.
- `EventCollector` utility for accumulating events.

**Key learning**: `WorkerSession` demonstrates the "borrow the backend" pattern.
It takes `&'b mut B`, which means only one session can exist at a time on a given
backend reference. This is correct — the backend is the serialization point. In the
runtime, each worker thread has its own backend connection (or the backend handles
internal locking), so sessions don't contend.

`StateTransitionEvent` is the Event Sourcing pattern applied to coordination. The
coordination layer is pure and testable — side effects (metrics, notifications) happen
in the caller. This is essential for deterministic simulation where events are captured
in the trace rather than triggering real notifications.

**Potential issues to watch**:
- `WorkerSession` holds `&'b mut B`, which means the Rust borrow checker enforces
  single-session-per-backend. This is great for correctness but means you can't
  have two workers sharing a single `InMemoryCoordinator` reference without `RefCell`
  or similar. In testing, create the coordinator with interior mutability or test
  one worker at a time.
- `claim_next_available` has a race condition in production (another worker may
  acquire the shard between `list_shards` and `acquire_and_restore`). This is
  handled by the `AlreadyLeased` error — the caller simply retries with the next
  shard. The default impl is correct but backends MAY override it with an atomic
  implementation (e.g., `SELECT ... FOR UPDATE SKIP LOCKED`).

---

### Implementation Summary

| Step | Files Created/Modified | Estimated Effort | Dependencies |
|------|----------------------|------------------|--------------|
| 1    | `coordination/cursor.rs`, `coordination/shard_spec.rs` | 2–3 hrs | B1 types |
| 2    | `coordination/record.rs`, `coordination/lease.rs`, `coordination/oplog.rs` | 2–3 hrs | Step 1 |
| 3    | `coordination/error.rs`, `coordination/validation.rs` | 1.5–2 hrs | Steps 1–2 |
| 4    | `coordination/trait.rs`, `coordination/in_memory.rs` | 3–4 hrs | Steps 1–3 |
| 5    | Extend `coordination/in_memory.rs` (split ops) | 2–3 hrs | Step 4 |
| 6    | `coordination/run.rs`, `coordination/admin.rs` | 2–3 hrs | Steps 1–5 |
| 7    | `coordination/session.rs`, `coordination/facade.rs`, `coordination/events.rs` | 1.5–2 hrs | Steps 1–6 |
| **Total** | | **~15–20 hrs** | |

Each step produces compilable code with test stubs. The in-memory backend from
Steps 4–6 becomes the reference implementation used by the deterministic simulator
and all conformance tests.

---

### Appendix A: File Organization

Recommended module structure within `coordination/`:

```
coordination/
├── mod.rs              (re-exports, module-level docs)
├── cursor.rs           (Step 1: Cursor, CursorAdvance, CursorBoundsCheck)
├── shard_spec.rs       (Step 1: ShardSpec, CursorSemantics, split validation)
├── record.rs           (Step 2: ShardStatus, ShardRecord, ShardSnapshot)
├── lease.rs            (Step 2: Lease, OpLogEntry, OpKind, OpResult)
├── split.rs            (Step 2: SplitReplacePlan/Result, SplitResidualPlan/Result, derive_split_shard_id)
├── error.rs            (Step 3: CoordError, all operation errors, From impls)
├── validation.rs       (Step 3: validate_lease, validate_cursor_update, check_op_idempotency)
├── traits.rs           (Step 4: CoordinationBackend trait, IdempotentOutcome, AcquireResult, RenewResult)
├── run.rs              (Step 6: RunStatus, RunConfig, RunRecord, RunManagement trait)
├── admin.rs            (Step 6: unpark, cancel, ManifestValidationError, validate_manifest)
├── session.rs          (Step 7: WorkerSession)
├── events.rs           (Step 7: StateTransitionEvent, EventCollector)
├── facade.rs           (Step 7: ShardClaiming, CoordinationFacade)
└── in_memory.rs        (Steps 4–6: InMemoryCoordinator, behind #[cfg(feature = "test-support")])
```

### Appendix B: Cross-Boundary Dependencies

B2 consumes from B1:
- `TenantId`, `RunId`, `ShardId`, `WorkerId`, `OpId`, `FenceEpoch`, `LogicalTime`,
  `JobId`, `PolicyHash`, `ShardKey`, `RunConfig` (basic), `Lease` (basic).
- `CanonicalBytes` trait, `domain_hasher`, `finalize_64`, `domain::SPLIT_ID_V1`,
  `domain::OP_PAYLOAD_V1`.
- `define_id_64!` macro (for types not already defined in B1).

B2 is consumed by:
- B3 (shard algebra): `ShardSpec`, `Cursor`, `SplitReplacePlan`, `SplitResidualPlan`.
- B4 (connector): `ShardSpec`, `Cursor`, `CursorSemantics`.
- B5 (persistence): `Cursor`, `ShardStatus`, `ParkReason`, `FenceEpoch`, `OpId`,
  `CoordinationBackend` (for checkpoint/complete calls in commit protocol).
