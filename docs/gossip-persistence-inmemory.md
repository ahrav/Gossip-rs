# gossip-persistence-inmemory

In-memory reference implementations of the `DoneLedger` and `FindingsSink`
persistence traits from `gossip-contracts::persistence`. Designed for
testing, conformance verification, and deterministic simulation.

> Source: `crates/gossip-persistence-inmemory/src/` (7 files).
> Passes `run_conformance` from `gossip-contracts::persistence::conformance`.
> For the persistence trait definitions see
> [boundary-5-persistence.md](gossip-contracts/boundary-5-persistence.md).

---

## 1. Source File Map

| File             | Role                                                                                      |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `lib.rs`         | Crate root, public re-exports, module declarations (`#![forbid(unsafe_code)]`)            |
| `store.rs`       | `InMemoryStoreCore<B>` generic infrastructure, `StoreBackend` trait, `StoreHandle`, condvar protocol |
| `done_ledger.rs` | `InMemoryDoneLedger` — `DoneLedger` trait impl, monotonic lattice merge                   |
| `findings.rs`    | `InMemoryFindingsSink` — `FindingsSink` trait impl, three-layer upsert, referential integrity |
| `pending.rs`     | `PendingOp<P, R>` and `PendingState<R>` — lifecycle types for the pending-write queue     |
| `error.rs`       | `InMemoryPersistenceError`, `InMemoryStoreKind`, `PendingWriteId`, `CompletionOrder`      |
| `tests.rs`       | Done-ledger and findings unit tests, fault injection coverage, delayed-completion scenarios  |

---

## 2. Architecture

Both `InMemoryDoneLedger` and `InMemoryFindingsSink` share the same
internal pattern via `InMemoryStoreCore<B>`:

```text
  InMemoryDoneLedger / InMemoryFindingsSink
    └─ Arc<InMemoryStoreCore<B>>
         ├─ Mutex<StoreState<B>>
         │    ├─ B::Durable          (HashMap-backed domain state)
         │    ├─ ops: HashMap<PendingWriteId, PendingOp>
         │    ├─ order: VecDeque<PendingWriteId>  (delayed-op FIFO)
         │    ├─ next_op_id: u64     (monotonically increasing)
         │    ├─ auto_complete: bool
         │    ├─ delay_next: usize
         │    ├─ fail_submit_remaining: usize
         │    └─ fail_commit_remaining: usize
         └─ Condvar                  (durability signaling)
```

Domain-specific behavior is injected through the `StoreBackend` trait:

| Implementor           | Payload type         | Durable state type  | Apply semantics                            |
| --------------------- | -------------------- | ------------------- | ------------------------------------------ |
| `DoneLedgerBackend`   | `DoneLedgerPayload`  | `DoneLedgerDurable` | Monotonic lattice merge per `DoneLedgerKey` |
| `FindingsBackend`     | `FindingsPayload`    | `FindingsDurable`   | Three-layer upsert with referential integrity |

Cloning either public type is cheap (`Arc` bump) and produces a handle
to the **same** shared state. This lets test harnesses inject faults on
one handle while the system under test uses another.

---

## 3. Completion Modes

Each store has two completion modes controlled by `auto_complete`:

- **Auto-complete (default):** writes apply immediately during
  `batch_upsert` / `upsert_batch`, so `handle.wait()` returns at once.
- **Delayed:** writes are enqueued as pending operations and only applied
  when explicitly released via `release_next`, `release_specific`, or
  `release_all`.

`delay_next_writes(count)` overrides `auto_complete` for a specific number
of submissions, allowing mixed-mode operation within a single test.

### Operation lifecycle

```text
  submit()
    │
    ├─ fail_submit_remaining > 0 ──► InjectedSubmissionFailure (no state change)
    │
    ├─ delay_next > 0 or !auto_complete
    │     └─► op inserted as Pending into ops + order queue
    │         └─► caller gets StoreHandle, wait() blocks on condvar
    │             └─► release_next / release_specific / release_all
    │                   └─► finish_op() applies payload ──► condvar.notify_all()
    │
    └─ auto_complete (default)
          └─► B::apply() runs immediately under the lock
              └─► op inserted as Finished ──► condvar.notify_all()
                  └─► wait() returns at once
```

---

## 4. InMemoryDoneLedger

Implements `DoneLedger` with `HashMap<DoneLedgerKey, DoneLedgerRecord>`
as durable state.

### Merge semantics

When a key already exists, records are merged via a monotonic lattice:

1. **Status**: lattice join via `DoneLedgerStatus::merge` — the higher
   rank wins (`FailedRetryable < FailedPermanent < Skipped < ScannedClean < ScannedWithFindings`).
2. **Metrics**: `bytes_scanned` takes the max. `findings_count` is
   status-aware (forced to 0 for `ScannedClean`, at least 1 for
   `ScannedWithFindings`).
3. **Provenance**: the "freshest" record wins — higher status rank, then
   later `finished_at`, then later `started_at`, otherwise keep existing.
4. **Error code**: cleared if the merged status is scanned (success absorbs
   prior errors).

### Read-side API

- `batch_get(tenant_id, policy_hash, &[OvidHash])` — point lookups.
- `get_record(key)` — single-key lookup.
- `snapshot()` — sorted durable snapshot for test assertions.

---

## 5. InMemoryFindingsSink

Implements `FindingsSink` with three `HashMap` tables as durable state:
`findings`, `occurrences`, and `observations`.

### Three-layer upsert

Processing order follows the parent-to-child hierarchy:

1. **Findings** (Layer 1): immutable insert-or-check. Duplicate keys with
   identical content are silently deduplicated; differing content produces
   `FindingConflict`.
2. **Occurrences** (Layer 2): same immutability rule. Each occurrence must
   reference a finding in the same batch or already durable.
   Missing parent → `MissingFinding`.
3. **Observations** (Layer 3): upsert semantics — identity fields must
   match, but provenance (`seen_at`, `location`, run context) may change
   across retries. Missing parent occurrence → `MissingOccurrence`.

### Validate-then-mutate

The function builds temporary `batch_*` maps and validates every invariant
as read-only lookups against the union of batch rows and durable rows.
Only after the entire payload passes validation are new rows inserted into
durable state. A validation error at any point aborts without mutation.

### Conformance probe

`InMemoryFindingsSink` implements `FindingsConformanceProbe`, exposing
`durable_counts()` for the backend-agnostic conformance harness to verify
idempotent replay.

### Read-side API

- `findings_snapshot()`, `occurrences_snapshot()`, `observations_snapshot()` — sorted snapshots.
- `get_finding(tenant_id, finding_id)`, `get_occurrence(...)`, `get_observation(...)` — point lookups.

---

## 6. Error Model

`InMemoryPersistenceError` is the unified error enum for both backends.
Variants fall into three categories:

| Category          | Variants                                              | Trigger                                    |
| ----------------- | ----------------------------------------------------- | ------------------------------------------ |
| Fault injection   | `InjectedSubmissionFailure`, `InjectedCommitFailure`  | Deterministic test-controlled failures     |
| Infrastructure    | `Poisoned`, `UnknownOperation`                        | Mutex poisoning or invalid op-id lookup    |
| Data integrity    | `MissingFinding`, `MissingOccurrence`, `FindingConflict`, `OccurrenceConflict`, `ObservationConflict`, `BatchValidation` | Referential integrity or immutability violations |

Supporting types:

| Type                | Purpose                                                    |
| ------------------- | ---------------------------------------------------------- |
| `InMemoryStoreKind` | `DoneLedger` or `Findings` discriminator for error context |
| `PendingWriteId`    | Opaque monotonic id for a pending write operation          |
| `CompletionOrder`   | `OldestFirst` (FIFO) or `NewestFirst` (LIFO) drain order  |

---

## 7. Fault Injection

Three independent, monotonically decremented counters control failure
behavior, checked in order during each submission:

1. **`fail_submit_remaining`** — rejects the request before any state
   mutation or handle creation. Simulates backend unavailability at the
   request-acceptance layer.
2. **`delay_next` / `auto_complete`** — determines whether the accepted
   write is applied immediately or enqueued as pending.
3. **`fail_commit_remaining`** — injects a failure at apply time (before
   any durable mutation). Simulates fsync/replication failures.

Public control methods:

- `fail_next_submissions(count)` — increment counter 1.
- `fail_next_commits(count)` — increment counter 3.
- `delay_next_writes(count)` — force-delay specific submissions.
- `set_auto_complete(bool)` — toggle global completion mode.

Release methods for delayed operations:

- `release_next(order)` — drain one from the queue (FIFO or LIFO).
- `release_specific(op_id)` — release a specific operation out of order.
- `release_all(order)` — drain all currently pending operations.

---

## 8. Conformance

Both backends pass `run_conformance` from
`gossip-contracts::persistence::conformance`, which verifies:

- Done-ledger idempotency and lattice merge (out-of-order writes converge).
- Findings idempotency and referential integrity (replay does not
  duplicate rows).
- Sensitive-type `Debug` redaction.
