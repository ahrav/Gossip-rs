# Coordination Error Model

## 1. Overview

The coordination error model provides compile-time-enforced, operation-specific
error types for every shard coordination operation. Rather than a single
mega-enum that forces callers to handle irrelevant variants, each operation
returns a dedicated error type that admits only the `CoordError` variants
semantically valid for that operation.

### Design philosophy

1. **Compile-time exhaustiveness over wildcard convenience.** Every
   `From<CoordError>` impl explicitly enumerates all variants (accepted and
   rejected). Adding a new `CoordError` variant triggers a compile error in
   every `From` impl, forcing a conscious routing decision for the new variant.
   Rejected variants map to `unreachable!()`.

2. **Security-first redaction.** Custom `Debug` and `Display` impls on error
   types redact sensitive fields (hash values, worker identities, raw key
   bytes) to prevent information leakage in logs and error messages.

3. **Idempotency before authorization.** The 3-step validation pipeline
   checks op-log replay *before* lease validation, so a worker that
   successfully completed an operation but crashed before receiving the
   response can retry and get the cached result -- even after the lease has
   expired or the shard has reached a terminal state.

4. **Operation-specific narrowing.** Callers get precise `match` arms: a
   `CheckpointError` can never produce `AlreadyLeased`, and a `RenewError`
   can never produce `OpIdConflict`.

5. **`#[non_exhaustive]` on all enums.** Adding variants is a non-breaking
   change for downstream crate consumers who match on them.

### Source files

| File | Lines | Role |
|------|:-----:|------|
| `crates/gossip-coordination/src/error.rs` | ~1,796 | `CoordError`, all shard-level operation errors, `AcquireScratch`, `FixedBuf`, `IdempotentOutcome` |
| `crates/gossip-coordination/src/validation.rs` | ~1,016 | `validate_lease`, `validate_cursor_update_pooled`, `check_op_idempotency` |
| `crates/gossip-coordination/src/lease.rs` | ~865 | `Lease`, `LeaseHolder`, `OpLogEntry`, `OpKind`, `OpResult` |
| `crates/gossip-coordination/src/run_errors.rs` | ~672 | `CreateRunError`, `RegisterShardsError`, `GetRunError`, `RunTransitionError`, `UnparkError` |
| `crates/gossip-coordination/src/split_execution.rs` | ~659 | `DerivedShardKind`, derived shard IDs, payload hash functions |
| `crates/gossip-coordination/src/facade.rs` | ~464 | `ClaimError`, `ShardClaiming` trait, default claim algorithm |

---

## 2. Error Hierarchy

### 2.1 CoordError -- the shared building block

`CoordError` (error.rs:112-201) is the core coordination error enum. It
provides the shared vocabulary of error conditions used across all
lease-gated shard operations. Individual operation error types wrap these
variants via `From<CoordError>` impls.

```text
CoordError (#[non_exhaustive])
├── ShardNotFound { shard: ShardKey }
├── TenantMismatch { expected: TenantId }
├── StaleFence { presented: FenceEpoch, current: FenceEpoch }
├── LeaseExpired { deadline: LogicalTime, now: LogicalTime }
├── ShardTerminal { shard: ShardKey, status: ShardStatus }
├── OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 }
├── CursorRegression { old_key: Option<usize>, new_key: Option<usize> }
├── CursorOutOfBounds(CursorOutOfBoundsDetail)
├── CursorKeyTooLarge { size: usize, max: usize }
├── CursorTokenTooLarge { size: usize, max: usize }
├── SplitInvalid(SplitValidationError)
└── CheckpointMissingKey
```

`CursorOutOfBoundsDetail` (error.rs:210-218) captures redacted byte lengths:

| Field | Type | Meaning |
|-------|------|---------|
| `last_key` | `usize` | Length of the cursor key that fell outside range |
| `spec_start` | `usize` | Length of shard's inclusive lower bound |
| `spec_end` | `usize` | Length of shard's exclusive upper bound |

### 2.2 Shard-level operation error types

Each shard operation has a dedicated error enum that wraps the subset of
`CoordError` variants relevant to that operation. The `From<CoordError>` impls
(error.rs:1053-1212) route accepted variants and `unreachable!()` on rejected
ones.

#### AcquireError (error.rs:358-431)

Acquire is special: it does NOT require a pre-existing lease, so it cannot
produce `StaleFence` or `LeaseExpired`. It has **no** `From<CoordError>` impl.

```text
AcquireError (#[non_exhaustive])
├── ShardNotFound { shard: ShardKey }
├── TenantMismatch { expected: TenantId }
├── ShardTerminal { shard: ShardKey, status: ShardStatus }
└── AlreadyLeased { current_owner: WorkerId, lease_deadline: LogicalTime }
```

#### RenewError (error.rs:440-485)

Renew extends a lease deadline without modifying shard progress. Excludes
`OpIdConflict`, cursor, and split variants.

```text
RenewError (#[non_exhaustive])
├── ShardNotFound { shard: ShardKey }
├── TenantMismatch { expected: TenantId }
├── StaleFence { presented: FenceEpoch, current: FenceEpoch }
├── LeaseExpired { deadline: LogicalTime, now: LogicalTime }
└── ShardTerminal { shard: ShardKey, status: ShardStatus }
```

#### CheckpointError (error.rs:498-645)

Checkpoint is the richest mutation (advances cursor, idempotent via op-log).
The widest error surface along with `CompleteError`. Excludes only
`SplitInvalid`. Has `From<SlabFull>` for `ResourceExhausted`.

```text
CheckpointError (#[non_exhaustive])
├── ShardNotFound { shard: ShardKey }
├── TenantMismatch { expected: TenantId }
├── StaleFence { presented: FenceEpoch, current: FenceEpoch }
├── LeaseExpired { deadline: LogicalTime, now: LogicalTime }
├── ShardTerminal { shard: ShardKey, status: ShardStatus }
├── OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 }
├── CursorRegression { old_key: Option<usize>, new_key: Option<usize> }
├── CursorOutOfBounds(CursorOutOfBoundsDetail)
├── CursorKeyTooLarge { size: usize, max: usize }
├── CursorTokenTooLarge { size: usize, max: usize }
├── CheckpointMissingKey
└── ResourceExhausted(SlabFull)
```

#### CompleteError (error.rs:656-803)

Shares most variants with `CheckpointError` (records a final cursor position).
Excludes `SplitInvalid`. Has `From<SlabFull>`.

```text
CompleteError (#[non_exhaustive])
├── ShardNotFound { shard: ShardKey }
├── TenantMismatch { expected: TenantId }
├── StaleFence { presented: FenceEpoch, current: FenceEpoch }
├── LeaseExpired { deadline: LogicalTime, now: LogicalTime }
├── ShardTerminal { shard: ShardKey, status: ShardStatus }
├── OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 }
├── CursorRegression { old_key: Option<usize>, new_key: Option<usize> }
├── CursorOutOfBounds(CursorOutOfBoundsDetail)
├── CursorKeyTooLarge { size: usize, max: usize }
├── CursorTokenTooLarge { size: usize, max: usize }
├── CheckpointMissingKey
└── ResourceExhausted(SlabFull)
```

#### ParkError (error.rs:812-902)

Park transitions a shard to the `Parked` terminal state. Carries
`OpIdConflict` but excludes all cursor variants, `CheckpointMissingKey`, and
`SplitInvalid`.

```text
ParkError (#[non_exhaustive])
├── ShardNotFound { shard: ShardKey }
├── TenantMismatch { expected: TenantId }
├── StaleFence { presented: FenceEpoch, current: FenceEpoch }
├── LeaseExpired { deadline: LogicalTime, now: LogicalTime }
├── ShardTerminal { shard: ShardKey, status: ShardStatus }
└── OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 }
```

#### SplitError (error.rs:912-1036)

Used by both split operations. Carries `OpIdConflict` and `SplitInvalid` but
excludes cursor variants and `CheckpointMissingKey`. Has `From<SlabFull>`.

```text
SplitError (#[non_exhaustive])
├── ShardNotFound { shard: ShardKey }
├── TenantMismatch { expected: TenantId }
├── StaleFence { presented: FenceEpoch, current: FenceEpoch }
├── LeaseExpired { deadline: LogicalTime, now: LogicalTime }
├── ShardTerminal { shard: ShardKey, status: ShardStatus }
├── OpIdConflict { op_id: OpId, expected_hash: u64, actual_hash: u64 }
├── SplitInvalid(SplitValidationError)
└── ResourceExhausted(SlabFull)
```

Type aliases (error.rs:989-995):
- `SplitReplaceError = SplitError`
- `SplitResidualError = SplitError`

### 2.3 Variant routing matrix

Each operation error type accepts a subset of `CoordError` variants via its
`From<CoordError>` impl. Rejected variants panic at `unreachable!()`.

| `CoordError` variant | Renew | Checkpoint | Complete | Park | Split |
|----------------------|:-----:|:----------:|:--------:|:----:|:-----:|
| `ShardNotFound` | yes | yes | yes | yes | yes |
| `TenantMismatch` | yes | yes | yes | yes | yes |
| `StaleFence` | yes | yes | yes | yes | yes |
| `LeaseExpired` | yes | yes | yes | yes | yes |
| `ShardTerminal` | yes | yes | yes | yes | yes |
| `OpIdConflict` | -- | yes | yes | yes | yes |
| `CursorRegression` | -- | yes | yes | -- | -- |
| `CursorOutOfBounds` | -- | yes | yes | -- | -- |
| `CursorKeyTooLarge` | -- | yes | yes | -- | -- |
| `CursorTokenTooLarge` | -- | yes | yes | -- | -- |
| `SplitInvalid` | -- | -- | -- | -- | yes |
| `CheckpointMissingKey` | -- | yes | yes | -- | -- |

`AcquireError` is excluded from the matrix because it defines its own variants
directly and has no `From<CoordError>` impl.

`ResourceExhausted(SlabFull)` is not routed through `CoordError` -- it
originates from `From<SlabFull>` impls on `CheckpointError`, `CompleteError`,
and `SplitError`.

### 2.4 Run-level error types

Run-level operations (run_errors.rs) use per-operation error types where
variants differ meaningfully, rather than the `From<CoordError>` narrowing
pattern. The only shared conversion across run-level types is
`From<RunOpIdConflict>`.

#### CreateRunError (run_errors.rs:61-105)

```text
CreateRunError (#[non_exhaustive])
├── InvalidConfig(RunConfigError)
├── RunAlreadyExists { run: RunId }
├── RegisterShardsFailed(RegisterShardsError)
├── GetRunFailed(GetRunError)
└── ConfigMismatch { run: RunId }
```

#### RegisterShardsError (run_errors.rs:130-229)

```text
RegisterShardsError (#[non_exhaustive])
├── RunNotFound
├── TenantMismatch { expected: TenantId }
├── WrongStatus { status: RunStatus }
├── ManifestInvalid(ManifestValidationError)
├── OpIdConflict(RunOpIdConflict)
├── ShardLimitExceeded { current, additional, max, scope: ShardLimitScope }
└── ResourceExhausted { resource: &'static str }
```

#### GetRunError (run_errors.rs:239-259)

```text
GetRunError (#[non_exhaustive])
├── RunNotFound
└── TenantMismatch { expected: TenantId }
```

#### RunTransitionError (run_errors.rs:272-348)

Shared by `complete_run`, `fail_run`, and `cancel_run`.

```text
RunTransitionError (#[non_exhaustive])
├── RunNotFound
├── TenantMismatch { expected: TenantId }
├── RunTerminal { status: RunStatus }
├── WrongStatus { status: RunStatus, target: RunStatus }
└── OpIdConflict(RunOpIdConflict)
```

#### UnparkError (run_errors.rs:358-414)

```text
UnparkError (#[non_exhaustive])
├── ShardNotFound
├── TenantMismatch { expected: TenantId }
├── RunTerminal { status: RunStatus }
├── NotParked { status: ShardStatus }
└── OpIdConflict(RunOpIdConflict)
```

### 2.5 ClaimError (facade.rs:50-161)

`ClaimError` is intentionally coarser than `AcquireError`: transient race
conditions are absorbed by the claim retry loop and surface as
`NoneAvailable` only when every candidate has been exhausted.

```text
ClaimError (#[non_exhaustive])
├── NoneAvailable { earliest_deadline: Option<LogicalTime> }
├── RunNotFound
├── TenantMismatch { expected: TenantId }
└── Throttled { retry_after: LogicalTime }
```

Has `From<GetRunError>` mapping `RunNotFound` and `TenantMismatch` 1:1.

---

## 3. Validation Pipeline

Every lease-gated mutation (checkpoint, complete, park, split) follows the
same three-step validation pipeline. The ordering is deliberate and
safety-critical.

### Step 1: Idempotency check -- `check_op_idempotency` (validation.rs:312-337)

Called **first** so that replays succeed even after the lease expires or the
shard reaches a terminal state.

**Three-way return:**

| Condition | Return | Caller action |
|-----------|--------|---------------|
| `op_id` not in log | `Ok(None)` | Proceed with fresh execution |
| `op_id` found, hash matches | `Ok(Some(entry))` | Return cached result (replay) |
| `op_id` found, hash differs | `Err(OpIdConflict)` | Reject -- caller reused an OpId with different parameters |

**Preconditions:** `payload_hash != 0` (asserted at runtime -- zero indicates
broken hashing).

**Op-log capacity:** The op-log is bounded to 16 entries. If an `OpId` has
been evicted, this function returns `Ok(None)` and the caller treats it as a
new operation. This is safe because:

- Terminal operations (complete, park, split_replace): the shard is terminal
  after first execution, so no further ops push entries and the terminal op's
  entry is never evicted.
- Non-terminal operations (checkpoint, split_residual): eviction requires 16+
  intervening ops within the same lease epoch. The fence epoch is the primary
  deduplication guard.

### Step 2: Lease validation -- `validate_lease` (validation.rs:114-180)

Five checks in security-priority order:

1. **Tenant isolation** (validation.rs:128-130) -- `record.tenant == tenant`.
   Checked first so a mismatch never reveals whether the shard is terminal,
   has a stale fence, or has an expired lease.

2. **Terminal status** (validation.rs:133-138) -- `!record.status.is_terminal()`.
   Fast rejection of dead shards before more expensive checks.

3. **Fence epoch** (validation.rs:141-146) -- `lease.fence() == record.fence_epoch`.
   Zombie worker fencing (Kleppmann protocol). A mismatch means another
   worker has since acquired the shard.

4. **Lease expiry** (validation.rs:151-159) -- `now < record.lease_deadline()`.
   If the fence check passes but the record has no lease holder (deadline is
   `None`), the record is in an inconsistent state and `StaleFence` is
   returned to force re-acquisition. The half-open interval means
   `now >= deadline` is expired.

5. **Owner divergence** (validation.rs:166-171) --
   `record.lease_owner() == Some(lease.owner())`. Defense-in-depth: catches
   identity mismatches when fence epochs agree (e.g., state reconstruction
   bugs).

**Preconditions:** `now > LogicalTime::ZERO` (asserted at runtime -- zero
indicates a broken clock).

**Postconditions** (on `Ok(())`):
- `record.tenant == tenant`
- `record.status` is non-terminal
- `lease.fence() == record.fence_epoch`
- `record.is_leased_at(now)` is `true`

### Step 3: Operation-specific validation

Varies by operation:

- **Checkpoint / Complete:** `validate_cursor_update_pooled`
  (validation.rs:209-262)
- **Split:** `validate_split_coverage` / `validate_residual_split`
  (from `gossip_contracts::coordination::shard_spec`)
- **Park:** No additional validation beyond Steps 1-2
- **Renew:** Step 1 is skipped (renew is not idempotent via OpId)

### Cursor validation -- `validate_cursor_update_pooled` (validation.rs:209-262)

Operates entirely on borrowed slices to avoid materializing owned cursor/spec
values on the checkpoint hot path. Checks five properties in order:

1. **Key presence** (validation.rs:216-218) -- `new_cursor.last_key()` must
   be `Some`. A checkpoint with no key represents no progress.

2. **Key size** (validation.rs:221-226) --
   `last_key.len() <= MAX_KEY_SIZE`. Defense-in-depth against oversized keys.

3. **Token size** (validation.rs:229-236) --
   `token.len() <= MAX_TOKEN_SIZE`. Defense-in-depth before storing in the
   slab.

4. **Monotonicity** (validation.rs:239-246) --
   `new_last_key >= old_last_key` (lexicographic). Prevents cursor regression
   within a lease epoch.

5. **Bounds** (validation.rs:249-259) -- `last_key` must fall within
   `[spec_start, spec_end)`. Empty `spec_start` / `spec_end` are treated as
   unbounded on that side.

The ordering matters: a missing key is reported before monotonicity, and
monotonicity is reported before bounds. This gives the caller the most
actionable error first.

---

## 4. Lease Semantics

### Lease structure (lease.rs:168-299)

`Lease` is the capability token returned by `acquire_and_restore_into` and
required by every lease-gated mutation. It carries:

| Field | Type | Purpose |
|-------|------|---------|
| `tenant` | `TenantId` | Tenant isolation scope |
| `run` | `RunId` | Run identity |
| `shard` | `ShardId` | Shard identity |
| `owner` | `WorkerId` | The worker holding this lease |
| `fence` | `FenceEpoch` | Monotonic fencing token |
| `deadline` | `LogicalTime` | Expiry time (half-open: `now < deadline` is active) |

Fields are private. The coordinator is the sole producer; workers receive
leases as opaque tokens.

**Construction panics:** `fence < FenceEpoch::INITIAL` or
`deadline == LogicalTime::ZERO`.

**Renewal:** `set_deadline` (lease.rs:287-298) extends the deadline without
changing the fence epoch. Panics if the new deadline is before the current
deadline (monotonicity violation). Equal deadlines are allowed (harmless
no-op).

### LeaseHolder (lease.rs:89-142)

Stored *inside* the `ShardRecord`. Bundles `owner: WorkerId` and
`deadline: LogicalTime` into a single value so the record stores
`Option<LeaseHolder>` instead of two separate `Option` fields -- making the
"both-present-or-both-absent" invariant structurally impossible to violate.

**Construction panics:** `deadline == LogicalTime::ZERO`.

### Fence epoch protocol

Every `acquire_and_restore_into` increments the shard's `fence_epoch`.
Subsequent mutations must present a lease whose `fence` matches the record's
current epoch. Stale epochs are rejected.

This implements the "fencing token protocol" from Kleppmann (2016): all
writes carry the fence epoch, and the backend rejects stale epochs. The epoch
is monotonically increasing -- it increments on every ownership transfer and
on administrative unpark.

### Lease expiry semantics

The coordinator uses a half-open interval:
- `now < deadline` -- lease is active
- `now >= deadline` -- lease is expired

At expiry, the coordinator rejects mutations and allows other workers to
re-acquire the shard.

---

## 5. Idempotency Log

### OpKind (lease.rs:350-478)

Operation kinds that participate in per-shard idempotency. `#[repr(u8)]` with
stable discriminants persisted in the op-log.

| Variant | Discriminant | Status Change | Lease Required? |
|---------|:------------:|---------------|:---------------:|
| `Checkpoint` | 0 | none (cursor advances) | yes |
| `Complete` | 1 | Active -> Done | yes |
| `Park` | 2 | Active -> Parked | yes |
| `SplitReplace` | 3 | Active -> Split | yes |
| `SplitResidual` | 4 | none (parent stays Active) | yes |
| `Unpark` | 5 | Parked -> Active (admin) | no |

### OpResult (lease.rs:497-554)

Stored result status for replay detection. `#[repr(u8)]`.

| Variant | Discriminant | Meaning |
|---------|:------------:|---------|
| `Completed` | 0 | Operation executed successfully |
| `Error` | 1 | Validation failed, shard NOT mutated |
| `Superseded` | 2 | Valid but overtaken by a later mutation |

### OpLogEntry (lease.rs:580-670)

A single entry in the bounded per-shard operation log.

| Field | Type | Purpose |
|-------|------|---------|
| `op_id` | `OpId` | Unique idempotency key |
| `kind` | `OpKind` | Operation type |
| `result` | `OpResult` | Cached outcome |
| `payload_hash` | `u64` | BLAKE3 fingerprint of operation parameters |
| `executed_at` | `LogicalTime` | Timestamp of first execution |

**Construction panics:** `executed_at == LogicalTime::ZERO` or
`payload_hash == 0`.

**Deduplication key:** `(OpId, payload_hash)`:
- Same pair -> idempotent replay, return cached result
- Same OpId, different hash -> conflict, reject
- OpId not found -> new operation (or evicted)

### Replay detection flow

1. Look up `OpId` in the shard's op-log (reverse scan, most-recent first).
2. **Found, same hash** -> return cached `OpResult` as
   `IdempotentOutcome::Replayed`.
3. **Found, different hash** -> reject as `OpIdConflict`.
4. **Not found** -> execute the mutation, record the entry, return
   `IdempotentOutcome::Executed`.

### IdempotentOutcome (error.rs:1738-1784)

```rust
pub enum IdempotentOutcome<T> {
    Executed(T),   // first execution
    Replayed(T),   // retry from op-log
}
```

Methods: `into_inner()`, `is_replay()`, `is_executed()`, `map()`, `as_ref()`.

Used by: checkpoint/complete return `IdempotentOutcome<()>`, split_replace
returns `IdempotentOutcome<SplitReplaceResult>`, split_residual returns
`IdempotentOutcome<SplitResidualResult>`.

---

## 6. Error Classification

### Retryable errors (worker should back off and retry)

| Error | Condition | Retry guidance |
|-------|-----------|----------------|
| `AlreadyLeased` | Another worker holds the shard | Wait until `lease_deadline` |
| `LeaseExpired` | Worker's lease expired | Re-acquire the shard |
| `ResourceExhausted(SlabFull)` | Byte slab full | Retry after freeing slab space |
| `ClaimError::NoneAvailable` | All shards claimed or terminal | Wait until `earliest_deadline` |
| `ClaimError::Throttled` | Worker claim cooldown active | Wait until `retry_after` |

### Fatal errors (worker must stop processing this shard)

| Error | Condition | Required action |
|-------|-----------|-----------------|
| `StaleFence` | Zombie worker -- another worker acquired the shard | Stop immediately, re-acquire |
| `ShardTerminal` | Shard is Done/Split/Parked | Stop, shard is finished |
| `OpIdConflict` | Same OpId reused with different payload | Bug in caller -- investigate |
| `CursorRegression` | New cursor key < old cursor key | Bug in caller -- safety invariant |
| `CursorOutOfBounds` | Cursor outside shard key range | Bug in caller -- safety invariant |
| `CursorKeyTooLarge` | Key exceeds `MAX_KEY_SIZE` | Bug in caller or corruption |
| `CursorTokenTooLarge` | Token exceeds `MAX_TOKEN_SIZE` | Bug in caller or corruption |
| `SplitInvalid` | Split coverage validation failed | Bug in caller -- fix split plan |
| `CheckpointMissingKey` | Checkpoint without `last_key` | Bug in caller -- include key |

### Escalation errors (always a bug or configuration error)

| Error | Condition | Required action |
|-------|-----------|-----------------|
| `TenantMismatch` | Cross-tenant request | Always a logic bug -- investigate |
| `ShardNotFound` | Shard not in store | Index corruption or race with deletion |

---

## 7. Security Redaction

All error types implement custom `Debug` and `Display` to prevent information
leakage.

| Error | Redacted Fields | Reason |
|-------|----------------|--------|
| `OpIdConflict` | `expected_hash`, `actual_hash` shown as `<redacted>` in Debug, omitted from Display | Prevents oracle attacks on payload hashing |
| `AlreadyLeased` | `current_owner` shown as `<redacted>` in both Debug and Display | Prevents worker identity leakage |
| `CursorRegression` | Raw key bytes replaced with `Some([N bytes])` summaries | Prevents data exfiltration via error messages |
| `CursorOutOfBounds` | Raw key bytes replaced with `[N bytes]` summaries | Same as above |
| `TenantMismatch` | Only `expected` (caller's tenant) exposed; actual tenant deliberately omitted | Prevents cross-tenant enumeration |

Run-level `OpIdConflict` variants wrap `RunOpIdConflict` as a tuple variant
(not exposing fields) to prevent external callers from extracting raw hash
values via pattern matching.

---

## 8. AcquireScratch and FixedBuf

### FixedBuf\<N\> (error.rs:1381-1483)

Fixed-capacity byte buffer with logical length tracking. Used for inline
storage of small variable-length fields without heap allocation.

| Method | Purpose |
|--------|---------|
| `new()` | Create empty buffer (zeroed backing, length 0) |
| `write(bytes, oversized_msg)` | Write bytes, panics if `bytes.len() > N` |
| `from_slice(bytes, oversized_msg)` | Convenience constructor: create and write |
| `read()` | Borrow written portion `&bytes[..len]` |
| `reset()` | Set logical length to zero (no zeroing) |
| `has_data()` | Returns `true` if `len > 0` |

Implements `Clone`, `PartialEq`, `Eq`, `Debug` (shows first 8 hex bytes).

### AcquireScratch (error.rs:1519-1682)

Caller-owned scratch buffer for allocation-free acquire snapshots.
Pre-allocates fixed-capacity arrays for every variable-size field in a shard
snapshot.

**Internal fields:**

| Field | Type | Purpose |
|-------|------|---------|
| `spec_start` | `FixedBuf<MAX_KEY_SIZE>` | Shard spec key range start |
| `spec_end` | `FixedBuf<MAX_KEY_SIZE>` | Shard spec key range end |
| `spec_metadata` | `FixedBuf<MAX_METADATA_SIZE>` | Shard spec opaque metadata |
| `cursor_last_key` | `FixedBuf<MAX_KEY_SIZE>` | Cursor last_key |
| `cursor_token` | `FixedBuf<MAX_TOKEN_SIZE>` | Cursor opaque token |
| `spawned` | `InlineVec<ShardId, MAX_SPAWNED_PER_SHARD>` | Spawned child shard IDs |

**Usage pattern:**

```text
let mut scratch = AcquireScratch::new();  // once per session
loop {
    let view = backend.acquire_and_restore_into(now, tenant, key, worker, &mut scratch)?;
    // use view.snapshot.spec(), view.snapshot.cursor(), etc.
    // scratch is overwritten on next call -- view is invalidated
}
```

**Methods:**

| Method | Purpose |
|--------|---------|
| `new()` | Create empty scratch |
| `reset()` | Reset all logical lengths |
| `write_spec(start, end, metadata)` | Copy spec bytes into scratch |
| `write_cursor(last_key, token)` | Copy cursor bytes into scratch |
| `write_spawned_iter(iter)` | Copy lineage IDs from iterator |
| `view(status, cursor_semantics, parent)` | Build `ShardSnapshotView` backed by scratch |

**Borrow-checker enforcement:** `acquire_and_restore_into` takes
`&'a mut AcquireScratch` and returns `AcquireResultView<'a>`, preventing
the caller from calling it again while the view is still live.

### Related result types

**ShardSnapshotView\<'a\>** (error.rs:1289-1353): Borrowed shard state
view backed by `AcquireScratch`. Fields: `status`, `spec`, `cursor`,
`cursor_semantics`, `parent`, `spawned`.

**AcquireResultView\<'a\>** (error.rs:1365-1375): Contains `lease: Lease`,
`snapshot: ShardSnapshotView<'a>`, `capacity: CapacityHint`.

**CapacityHint** (error.rs:1236-1269): Advisory capacity information
piggybacked on acquire/renew results. Fields: `available_count: u32`,
`earliest_deadline: Option<LogicalTime>`. Fail-open advisory metadata.

**RenewResult** (error.rs:1688-1699): Contains `new_deadline: LogicalTime`,
`capacity: CapacityHint`.

---

## 9. Integration: Error Flow

### Shard-level flow

```text
  ┌──────────────────────┐
  │   Caller (facade,    │
  │   orchestrator)      │
  │                      │
  │  calls checkpoint()  │
  └──────────┬───────────┘
             │
  ┌──────────▼───────────┐
  │  check_op_idempotency│ ──▶ Ok(Some(entry)) → return Replayed
  │  (validation.rs)     │ ──▶ Err(OpIdConflict) → CoordError
  │                      │ ──▶ Ok(None) → continue
  └──────────┬───────────┘
             │
  ┌──────────▼───────────┐
  │  validate_lease       │ ──▶ Err(TenantMismatch|ShardTerminal|
  │  (validation.rs)      │      StaleFence|LeaseExpired) → CoordError
  │                       │ ──▶ Ok(()) → continue
  └──────────┬────────────┘
             │
  ┌──────────▼───────────────┐
  │  validate_cursor_update  │ ──▶ Err(CheckpointMissingKey|CursorKeyTooLarge|
  │  _pooled (validation.rs) │      CursorTokenTooLarge|CursorRegression|
  │                          │      CursorOutOfBounds) → CoordError
  │                          │ ──▶ Ok(()) → continue
  └──────────┬───────────────┘
             │
  ┌──────────▼───────────┐
  │  Apply mutation       │
  │  (in_memory.rs)       │ ──▶ SlabFull → CheckpointError::ResourceExhausted
  └──────────┬────────────┘
             │
  ┌──────────▼───────────┐
  │  ? operator triggers  │ ──▶ From<CoordError> for CheckpointError
  │  From conversion      │     (error.rs:1053-1088)
  └──────────┬────────────┘
             │
  ┌──────────▼───────────┐
  │  Return to caller     │ ──▶ Result<IdempotentOutcome<()>, CheckpointError>
  └──────────────────────┘
```

The `?` operator in backend methods uses `From<CoordError>` conversions
automatically. `CoordError` is the shared intermediate type that all
validation functions return; it gets narrowed to the operation-specific error
type at the backend boundary.

### Claim-level flow

```text
  ┌────────────────────────┐
  │  ShardClaiming::        │
  │  claim_next_available   │
  └──────────┬──────────────┘
             │
  ┌──────────▼───────────────┐
  │  collect_claim_candidates│ ──▶ Err(GetRunError) → From<GetRunError>
  │  _into (RunManagement)   │     → ClaimError::RunNotFound|TenantMismatch
  └──────────┬───────────────┘
             │
  ┌──────────▼───────────────┐
  │  For each candidate:     │
  │  acquire_and_restore_into│ ──▶ Ok → return success
  │                          │ ──▶ Err(AlreadyLeased|ShardTerminal|
  │                          │      ShardNotFound) → skip, try next
  │                          │ ──▶ Err(TenantMismatch) → fail immediately
  └──────────┬───────────────┘
             │ all candidates exhausted
  ┌──────────▼───────────────┐
  │  ClaimError::NoneAvailable│
  │  { earliest_deadline }    │
  └───────────────────────────┘
```

### Run-level flow

Run-level operations use per-operation error types directly. The shared
`From<RunOpIdConflict>` conversion routes idempotency conflicts into each
type's `OpIdConflict` variant. Run-level errors do not go through
`CoordError`.

---

## 10. Source of Truth Table

### Shard-level error types (error.rs)

| Type | Location | Variants |
|------|----------|:--------:|
| `CoordError` | error.rs:112-201 | 12 |
| `CursorOutOfBoundsDetail` | error.rs:210-218 | struct (3 fields) |
| `AcquireError` | error.rs:358-431 | 4 |
| `RenewError` | error.rs:440-485 | 5 |
| `CheckpointError` | error.rs:498-645 | 12 |
| `CompleteError` | error.rs:656-803 | 12 |
| `ParkError` | error.rs:812-902 | 6 |
| `SplitError` | error.rs:912-1036 | 8 |
| `SplitReplaceError` (alias) | error.rs:989 | = `SplitError` |
| `SplitResidualError` (alias) | error.rs:995 | = `SplitError` |

### From impls (error.rs)

| Conversion | Location |
|------------|----------|
| `From<CoordError> for CheckpointError` | error.rs:1053-1088 |
| `From<CoordError> for CompleteError` | error.rs:1090-1124 |
| `From<CoordError> for ParkError` | error.rs:1126-1156 |
| `From<CoordError> for SplitError` | error.rs:1158-1188 |
| `From<CoordError> for RenewError` | error.rs:1190-1212 |
| `From<SlabFull> for CheckpointError` | error.rs:641-645 |
| `From<SlabFull> for CompleteError` | error.rs:799-803 |
| `From<SlabFull> for SplitError` | error.rs:1032-1036 |

### Result and outcome types (error.rs)

| Type | Location | Purpose |
|------|----------|---------|
| `CapacityHint` | error.rs:1236-1269 | Advisory shard availability |
| `ShardSnapshotView<'a>` | error.rs:1289-1353 | Borrowed shard state view |
| `AcquireResultView<'a>` | error.rs:1365-1375 | Lease + snapshot + capacity |
| `FixedBuf<N>` | error.rs:1381-1483 | Fixed-capacity byte buffer |
| `AcquireScratch` | error.rs:1519-1682 | Caller-owned scratch buffer |
| `RenewResult` | error.rs:1688-1699 | Renewal result |
| `IdempotentOutcome<T>` | error.rs:1738-1784 | Executed vs. Replayed wrapper |

### Validation functions (validation.rs)

| Function | Location | Returns |
|----------|----------|---------|
| `validate_lease` | validation.rs:114-180 | `Result<(), CoordError>` |
| `validate_cursor_update_pooled` | validation.rs:209-262 | `Result<(), CoordError>` |
| `check_op_idempotency` | validation.rs:312-337 | `Result<Option<&OpLogEntry>, CoordError>` |

### Lease types (lease.rs)

| Type | Location | Purpose |
|------|----------|---------|
| `LeaseHolder` | lease.rs:89-142 | Owner + deadline stored in `ShardRecord` |
| `Lease` | lease.rs:168-299 | Capability token returned to workers |
| `OpKind` | lease.rs:350-478 | Operation type discriminant (`#[repr(u8)]`) |
| `OpResult` | lease.rs:497-554 | Cached result status (`#[repr(u8)]`) |
| `OpLogEntry` | lease.rs:580-670 | Single op-log entry |

### Run-level error types (run_errors.rs)

| Type | Location | Variants |
|------|----------|:--------:|
| `CreateRunError` | run_errors.rs:61-105 | 5 |
| `RegisterShardsError` | run_errors.rs:130-229 | 7 |
| `GetRunError` | run_errors.rs:239-259 | 2 |
| `RunTransitionError` | run_errors.rs:272-348 | 5 |
| `UnparkError` | run_errors.rs:358-414 | 5 |

### Facade-level error (facade.rs)

| Type | Location | Variants |
|------|----------|:--------:|
| `ClaimError` | facade.rs:50-161 | 4 |

### Split execution types (split_execution.rs)

| Type | Location | Purpose |
|------|----------|---------|
| `DerivedShardKind` | split_execution.rs:88-125 | Child vs. Residual discriminant |
| `SplitReplaceResult` | split_execution.rs:149-154 | Child shard IDs from split-replace |
| `SplitResidualResult` | split_execution.rs:163-168 | Residual shard ID from split-residual |

---

## 11. References

- Kleppmann, M. "How to do distributed locking." 2016.
  https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html
- Gray, C. and Cheriton, D. "Leases: An Efficient Fault-Tolerant Mechanism
  for Distributed File Cache Consistency." SOSP 1989.
- Stripe. "Designing robust and predictable APIs with idempotency."
  (Brandur Leach, 2017).
- Cho, J. et al. "Breakwater: Overload Control for Microservices." OSDI 2020.
  (Credit piggybacking pattern used for `CapacityHint`.)
