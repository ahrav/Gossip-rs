# Shard Fencing TLA+ Specification

TLA+ specification and model-checking infrastructure for the epoch-based
shard fencing protocol. The spec exhaustively verifies mutual exclusion (P1),
zombie rejection (P2), split atomicity (P3), cursor monotonicity (S5), fence
monotonicity (S2), terminal irreversibility (S3), and eventual re-acquire
(INV-L01) across all reachable states.

For the protocol design see
[boundary-2-coordination.md](../../docs/boundary-2-coordination.md).
For implementation-level testing see
[coordination-testing.md](../../docs/coordination-testing.md).
For the simulation harness see
[simulation-harness.md](../../docs/simulation-harness.md).

---

## 1. What the Specification Models

The specification operates at a **logical abstraction** above the Rust
implementation:

- **Logical clock** -- a single integer (`clock`) models wall-clock time.
  Non-deterministic `Tick` advances capture all possible timing behaviors.
- **Abstract integer cursors** -- cursor positions are integers `0..MaxCursor`,
  not byte-key ranges. This is sufficient to verify monotonicity and
  non-regression without modeling lexicographic ordering.
- **Single tenant** -- tenant isolation (validate_lease check 1) is omitted.
  The protocol's fencing and lifecycle properties are tenant-independent.
- **Fixed topology** -- one parent shard and two children. Enough to verify
  split atomicity without modeling arbitrary fan-out.

### What is NOT modeled

| Omission | Reason |
|----------|--------|
| Op-log idempotency | Orthogonal to fencing; tested exhaustively by Tier 1-3 tests |
| Tenant isolation | Single-tenant model; SEC-1 tested by unit and conformance tests |
| Byte-key ranges | Abstract cursors suffice for monotonicity; bounds tested in Rust |
| `renew` | Lease extension without fence bump; does not affect safety properties |
| `split_residual` | Parent stays Active; same fencing semantics as Checkpoint |

### Variable mapping

| TLA+ variable | Type | Rust equivalent |
|---------------|------|-----------------|
| `status` | `[AllShards -> StatusSet]` | `ShardRecord.status` (`ShardStatus`) |
| `fence_epoch` | `[AllShards -> 0..MaxEpoch]` | `ShardRecord.fence_epoch` (`FenceEpoch`) |
| `owner` | `[AllShards -> Workers ∪ {none}]` | `ShardRecord.lease.map(\|l\| l.owner)` |
| `deadline` | `[AllShards -> 0..MaxTime]` | `ShardRecord.lease.map(\|l\| l.deadline)` |
| `cursor` | `[AllShards -> 0..MaxCursor]` | `ShardRecord.cursor` (`Cursor`) |
| `spawned` | `[AllShards -> SUBSET AllShards]` | `ShardRecord.spawned` (`Vec<ShardId>`) |
| `prev_cursor` | `[AllShards -> 0..MaxCursor]` | Ghost variable (no Rust equivalent) |
| `worker_epoch` | `[Workers -> [AllShards -> 0..MaxEpoch]]` | `Lease.fence` (cached by worker) |
| `clock` | `1..MaxTime` | `LogicalTime` parameter passed to operations |

### Action mapping

| TLA+ action | Rust function | File | Lease-gated? |
|-------------|---------------|------|:------------:|
| `Acquire` | `acquire_and_restore` | `in_memory.rs:413` | No |
| `Checkpoint` | `checkpoint` | `in_memory.rs:508` | Yes |
| `Complete` | `complete` | `in_memory.rs:550` | Yes |
| `Park` | `park_shard` | `in_memory.rs:596` | Yes |
| `SplitReplace` | `split_replace` | `in_memory.rs:649` | Yes |
| `Unpark` | `unpark_shard` | `in_memory.rs:1687` | No |
| `Tick` | (environment) | N/A -- models time passing | N/A |

`FenceGuard(w, s)` in the TLA+ spec encodes `validate_lease` checks 2-4
from `validation.rs`: terminal status rejection, fence epoch comparison, and
lease expiry. Check 1 (tenant isolation) and check 5 (owner divergence) are
omitted or derivable within the single-tenant model.

---

## 2. Properties Verified

### Safety invariants (state predicates)

| TLA+ name | Sim label | Property |
|-----------|-----------|----------|
| `TypeOK` | -- | Type invariant: all variables in declared domains |
| `MutualExclusion` | S1 | At most one worker with valid lease per shard (tautological for function-valued `owner`; `ZombieRejection` is the operative guarantee) |
| `ZombieRejection` | -- | Stale-epoch worker cannot hold valid lease |
| `SplitAtomicity` | S7 | Split shards have non-empty spawned set; all children are Active or beyond |
| `ChildImpliesParentSplit` | S7 | Child becoming non-NotCreated implies parent is Split |
| `TerminalUnleased` | S4 | Terminal shards (Done, Split, Parked) hold no lease |
| `FenceEpochSanity` | S2 | Non-NotCreated shards have fence_epoch >= 1 (INITIAL) |
| `CursorMonotonicity` | S5 | Cursor never decreases (ghost variable comparison) |

### Action properties (temporal)

| TLA+ name | Sim label | Property |
|-----------|-----------|----------|
| `AlwaysFenceMonotonicity` | S2 | `[][fence_epoch'[s] >= fence_epoch[s]]_vars` |
| `AlwaysTerminalIrreversibility` | S3 | `[][Done => Done' /\ Split => Split']_vars` |
| `AlwaysCursorNonRegression` | S5 | `[][cursor'[s] >= cursor[s]]_vars` |

### Liveness

| TLA+ name | Sim label | Property |
|-----------|-----------|----------|
| `Liveness` | INV-L01 | Active, unleased shard with room to lease is eventually leased |

The `LiveSpec` excludes `Tick` from the next-state relation. `Tick` is an
environment action (adversarial timing); per Lamport's convention, no
fairness is applied to environment actions. In a bounded model, unconstrained
`Tick` can advance the clock past `MaxTime` before `Acquire` fires, producing
instantly-expired leases that starve acquisition. Removing `Tick` freezes
the clock at 1, verifying the protocol's acquisition liveness under
favorable timing. The full expire-and-re-acquire cycle is verified by the
safety spec (which explores all timing interleavings) and the simulation
tests.

### Non-vacuity checks

| TLA+ name | Purpose |
|-----------|---------|
| `EventuallyAcquired` | Some worker eventually acquires some shard |
| `EventuallySplit` | Parent eventually reaches Split status |
| `EventuallyDone` | Some shard eventually reaches Done status |

These temporal properties should PASS under `LiveSpec`. They confirm the
model is not vacuously true (i.e., the state space is reachable enough for
the properties to be meaningful).

---

## 3. Running TLC

### Prerequisites

- **Java 11+** on `PATH`.
- `tla2tools.jar` at `specs/tla2tools.jar` (already checked in).

### Configuration comparison

| Config file | Workers | Constants | Purpose |
|-------------|:-------:|-----------|---------|
| `ShardFencing_dev.cfg` | 2 | MaxEpoch=2, MaxTime=4 | Fast iteration during development |
| `ShardFencing.cfg` | 3 | MaxEpoch=3, MaxTime=6 | Production safety check (exhaustive) |
| `ShardFencing_liveness.cfg` | 2 | MaxEpoch=4, MaxTime=8 | Liveness verification (no SYMMETRY) |

### Commands

Run from the repository root.

**Development (fast feedback):**

```bash
java -XX:+UseParallelGC -cp specs/tla2tools.jar tlc2.TLC \
  -workers auto -deadlock \
  -config specs/coordination/ShardFencing_dev.cfg \
  specs/coordination/ShardFencing.tla
```

**Production safety (exhaustive):**

```bash
java -XX:+UseParallelGC -cp specs/tla2tools.jar tlc2.TLC \
  -workers auto -deadlock \
  -config specs/coordination/ShardFencing.cfg \
  specs/coordination/ShardFencing.tla
```

**Liveness:**

```bash
java -XX:+UseParallelGC -cp specs/tla2tools.jar tlc2.TLC \
  -workers auto -deadlock -lncheck final \
  -config specs/coordination/ShardFencing_liveness.cfg \
  specs/coordination/ShardFencing.tla
```

### Notes

- **`-deadlock`** disables TLC's deadlock detection. The spec intentionally
  reaches terminal states where no further actions are enabled.
- **`-lncheck final`** is required for liveness checking; it tells TLC to
  check liveness properties only on the final state graph (sound and faster).
- **SYMMETRY** is used for safety configs (workers are interchangeable) but
  NOT for liveness (SYMMETRY is unsound with liveness properties).
- The liveness config uses NO CONSTRAINT. State-space constraints are unsound
  with liveness checking because they can prune paths needed to satisfy
  temporal properties.

### Expected output

**Success:**

```
Model checking completed. No error has been found.
```

**Failure (invariant violation):**

```
Error: Invariant MutualExclusion is violated.
```

Followed by a counterexample trace showing the sequence of states leading to
the violation. The trace is the primary debugging tool -- it shows exactly
which action sequence breaks the invariant.

---

## 4. Mutation Tests

The mutation test suite validates that the invariants are necessary -- that
each one catches real bugs and is not vacuously true.

### How it works

Each mutation creates a copy of the spec with one deliberate defect, runs
TLC, and checks that the expected invariant is violated (or that a
non-vacuity check passes).

### Mutation table

| # | Mutation | Expected violation | Guard validated |
|:-:|----------|--------------------|-----------------|
| 1 | Remove `worker_epoch` cache from Acquire | `ZombieRejection` | Epoch caching prevents zombies |
| 2 | Remove `status = Active` check from Acquire | `TerminalUnleased` | Terminal shards reject acquisition |
| 3 | Don't clear owner in Complete | `TerminalUnleased` | Terminal transitions release leases |
| 4 | Don't activate children in SplitReplace | `SplitAtomicity` | Children must be Active after split |
| 5 | Allow `Done -> Active` in Unpark | `TerminalIrreversibility` | Done is irreversible |
| 6 | Swap cursor/prev_cursor in Checkpoint | `CursorMonotonicity` | Cursor must advance, not regress |
| 7 | Non-vacuity: `EventuallyAcquired` under `LiveSpec` | (should pass) | Acquisition is satisfiable under WF |
| 8 | Non-vacuity: `Liveness` (INV-L01) under `LiveSpec` | (should pass) | Liveness property is satisfiable |
| 9 | Keep parent Active in SplitReplace | `ChildImpliesParentSplit` | Parent must transition to Split |
| 10 | Set children `fence_epoch = 0` in SplitReplace | `FenceEpochSanity` | Children start at INITIAL (1) |
| 11 | Reset epoch to 0 in Unpark | `AlwaysFenceMonotonicity` | Fence epoch never decreases |
| 12 | Park resets cursor to 0 | `AlwaysCursorNonRegression` | Cursor never regresses |
| 13 | Non-vacuity: `NeverSplit` (negation invariant) | `NeverSplit` | Split state is reachable |
| 14 | Non-vacuity: `NeverDone` (negation invariant) | `NeverDone` | Done state is reachable |

### Running

```bash
bash specs/coordination/run_mutations.sh
```

### Expected output

```
Total: 14  Passed: 14  Failed: 0
```

---

## 5. Three Verification Layers

The TLA+ spec is one of three complementary verification layers. Each catches
a different class of defect.

```text
     TLA+ Model Checking          Simulation (Tier 4)          Runtime Assertions
    ─────────────────────    ───────────────────────────    ─────────────────────────
    Verifies: protocol       Verifies: Rust impl of the    Verifies: production
    design (abstract model)  protocol under fault injection state consistency

    Exhaustive within its    Randomized but exercises      Last line of defense;
    abstraction boundary     real Rust code paths          panics before corruption

    Catches: design bugs     Catches: implementation       Catches: state corruption
    (missing guards, wrong   bugs (off-by-one, wrong       from hardware faults,
    state transitions,       enum variant, hash            storage bugs, or code
    impossible-to-reach      collisions, edge cases        paths missed by tests
    liveness)                in split/cursor logic)

    Limitation: abstract     Limitation: probabilistic,    Limitation: reactive,
    model may diverge from   not exhaustive; only as       not preventive; crash
    implementation           good as the seed coverage     is the recovery mechanism
```

The key insight: TLA+ is exhaustive within its abstraction (it finds design
bugs that no amount of testing can catch), but it operates on an abstract
model that omits implementation details. Simulation exercises the real Rust
code under fault injection (it finds implementation bugs that formal
verification cannot reach). Runtime assertions are the last line of defense
in production.

### References

- Newcombe, C. et al. "How Amazon Web Services Uses Formal Methods."
  Communications of the ACM 58(4), April 2015.
- Lamport, L. *Specifying Systems: The TLA+ Language and Tools for Hardware
  and Software Engineers.* Addison-Wesley, 2002.

---

## 6. Files

| File | Purpose |
|------|---------|
| `ShardFencing.tla` | TLA+ specification (437 lines) |
| `ShardFencing.cfg` | Production safety config (3 workers, exhaustive) |
| `ShardFencing_dev.cfg` | Development safety config (2 workers, fast) |
| `ShardFencing_liveness.cfg` | Liveness config (no SYMMETRY, no CONSTRAINT) |
| `run_mutations.sh` | Mutation test suite (14 mutations) |

The `tla2tools.jar` model checker lives at `specs/tla2tools.jar` (shared
across all specs in the repository).
