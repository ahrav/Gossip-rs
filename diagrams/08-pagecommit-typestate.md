# PageCommit Typestate Machine

> **Implementation status: Contract Spec.** The PageCommit typestate is defined as a
> contract in `persistence/mod.rs`. The in-memory reference backend exercises the full
> protocol. A durable persistence backend is pending. This document describes the target
> design.

The `PageCommit` type encodes a critical safety invariant directly into the Rust
type system: **a page of scan results cannot be committed until it has been
sealed, and committed results cannot be modified after the fact.** This is the
typestate pattern -- the state of the commit is tracked as a generic type
parameter, and invalid transitions become compile-time errors rather than runtime
panics. The result is zero-cost (the state markers are zero-sized types erased
at compile time) and total (there is no way to circumvent the protocol without
`unsafe`).

PageCommit lives in the **B5 Persistence** boundary. It is the final step in
the worker's hot path: after scanning a page of items, the worker must
atomically persist three things -- findings, done-ledger entries, and the cursor
advancement. If any one of these three writes succeeds without the others, the
system enters an inconsistent state that produces **false negatives** -- the
worst possible failure mode for a secret scanner, because secrets silently slip
through undetected.

> **Notation.** Solid lines represent valid transitions. Dashed lines represent
> compile-error paths (transitions that the type system prevents). All diagrams
> use the B5 Persistence color palette (purple theme: fill `#8B5CF6`, light fill
> `#EDE9FE`, stroke `#5B21B6`).

---

## 1. Typestate State Machine

The PageCommit lifecycle has exactly three states. Each state is a zero-sized
marker type (`Accumulating`, `Sealed`, `Committed`) that parameterizes the
`PageCommit<S>` struct. The methods available on `PageCommit` change depending
on the state parameter: you can call `add_finding()` on `PageCommit<Accumulating>`
but not on `PageCommit<Sealed>`, and you can call `commit()` on
`PageCommit<Sealed>` but not on `PageCommit<Accumulating>`. These constraints
are enforced at compile time -- there is no runtime state enum, no match
statement, no panic path.

The self-transitions on `Accumulating` represent the collection phase: the
worker adds findings and done-ledger keys one at a time as it processes each
item in the page. Once all items are processed, `seal()` consumes the
`PageCommit<Accumulating>` and returns a `PageCommit<Sealed>`, making further
additions impossible. The `commit()` method on `Sealed` performs the atomic
write and returns `PageCommit<Committed>`, from which the worker extracts the
next cursor to advance the coordinator.

```mermaid
%% Diagram: typestate-state-machine
stateDiagram-v2
    direction LR

    [*] --> Accumulating : new(next_cursor)

    Accumulating --> Accumulating : add_finding()
    Accumulating --> Accumulating : add_done_key()
    Accumulating --> Sealed : seal()

    Sealed --> Committed : commit()

    Committed --> [*] : next_cursor()

    note right of Accumulating
        Type: PageCommit< Accumulating >
        Methods: add_finding(), add_done_key(), seal()
        Semantics: Collecting findings and done-ledger entries
    end note

    note right of Sealed
        Type: PageCommit< Sealed >
        Methods: commit()
        Semantics: All entries collected, ready for atomic write
    end note

    note right of Committed
        Type: PageCommit< Committed >
        Methods: next_cursor(), findings(), done_keys()
        Semantics: Write succeeded, results extractable
    end note

    classDef accumulatingState fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    classDef sealedState fill:#8B5CF6,stroke:#5B21B6,color:#FFFFFF
    classDef committedState fill:#8B5CF6,stroke:#5B21B6,color:#FFFFFF

    class Accumulating accumulatingState
    class Sealed sealedState
    class Committed committedState
```

The three states correspond to three phases of a page commit:

| State | Type Parameter | Available Methods | Semantics |
|:------|:---------------|:------------------|:----------|
| **Accumulating** | `PageCommit<Accumulating>` | `add_finding()`, `add_done_key()`, `seal()` | Collecting results from the current page scan |
| **Sealed** | `PageCommit<Sealed>` | `commit()` | Collection complete, ready for atomic persistence |
| **Committed** | `PageCommit<Committed>` | `next_cursor()`, `findings()`, `done_keys()` | Write succeeded, results are immutable and extractable |

---

## 2. Partial Write Failure Scenarios

Why does atomicity matter? Consider what happens if the three writes
(done-ledger, findings, cursor advancement) are performed independently and one
fails. There are three failure scenarios, and **two of the three produce false
negatives** -- secrets that the scanner processed but never reported. The only
acceptable failure mode is the one where findings are written but done-ledger
entries are not, because that produces duplicates on re-scan rather than missed
secrets.

The PageCommit's atomic `commit()` method eliminates all three partial-failure
scenarios by bundling the writes into a single transaction. Either all three
succeed, or none of them do. On failure, the cursor is not advanced, so the
page will be re-scanned on the next attempt.

```mermaid
%% Diagram: partial-write-failure-scenarios
graph TD
    START(["Page scan complete:<br/>3 writes needed"])

    START --> S1_TITLE
    START --> S2_TITLE
    START --> S3_TITLE

    subgraph scenario1 ["Scenario 1: Done-Ledger Only"]
        S1_TITLE["Done-ledger write"]
        S1_DONE["Mark items done"]
        S1_FIND["Write findings"]
        S1_CURS["Advance cursor"]
        S1_RESULT["Items marked 'done'<br/>but findings LOST"]
        S1_VERDICT["FALSE NEGATIVES"]

        S1_TITLE --> S1_DONE
        S1_DONE -->|"OK"| S1_FIND
        S1_FIND -->|"FAIL"| S1_CURS
        S1_CURS -->|"FAIL"| S1_RESULT
        S1_RESULT --> S1_VERDICT
    end

    subgraph scenario2 ["Scenario 2: Findings Only"]
        S2_TITLE["Findings write"]
        S2_DONE["Mark items done"]
        S2_FIND["Write findings"]
        S2_CURS["Advance cursor"]
        S2_RESULT["Duplicate findings<br/>on re-scan"]
        S2_VERDICT["ACCEPTABLE<br/>(idempotent)"]

        S2_TITLE --> S2_DONE
        S2_DONE -->|"FAIL"| S2_FIND
        S2_FIND -->|"OK"| S2_CURS
        S2_CURS -->|"FAIL"| S2_RESULT
        S2_RESULT --> S2_VERDICT
    end

    subgraph scenario3 ["Scenario 3: Cursor Only"]
        S3_TITLE["Cursor advance"]
        S3_DONE["Mark items done"]
        S3_FIND["Write findings"]
        S3_CURS["Advance cursor"]
        S3_RESULT["Page skipped<br/>on resume"]
        S3_VERDICT["FALSE NEGATIVES"]

        S3_TITLE --> S3_DONE
        S3_DONE -->|"FAIL"| S3_FIND
        S3_FIND -->|"FAIL"| S3_CURS
        S3_CURS -->|"OK"| S3_RESULT
        S3_RESULT --> S3_VERDICT
    end

    ATOMIC(["PageCommit::commit()<br/>ALL THREE writes in one transaction<br/>All succeed or all fail"])

    S1_VERDICT --> ATOMIC
    S2_VERDICT --> ATOMIC
    S3_VERDICT --> ATOMIC

    style START fill:#EDE9FE,stroke:#5B21B6,color:#000
    style ATOMIC fill:#8B5CF6,stroke:#5B21B6,color:#FFF

    style S1_DONE fill:#DCFCE7,stroke:#166534,color:#000
    style S1_FIND fill:#FEE2E2,stroke:#991B1B,color:#000
    style S1_CURS fill:#FEE2E2,stroke:#991B1B,color:#000
    style S1_RESULT fill:#FEE2E2,stroke:#991B1B,color:#000
    style S1_VERDICT fill:#EF4444,stroke:#991B1B,color:#FFF

    style S2_DONE fill:#FEE2E2,stroke:#991B1B,color:#000
    style S2_FIND fill:#DCFCE7,stroke:#166534,color:#000
    style S2_CURS fill:#FEE2E2,stroke:#991B1B,color:#000
    style S2_RESULT fill:#FEF9C3,stroke:#854D0E,color:#000
    style S2_VERDICT fill:#FACC15,stroke:#854D0E,color:#000

    style S3_DONE fill:#FEE2E2,stroke:#991B1B,color:#000
    style S3_FIND fill:#FEE2E2,stroke:#991B1B,color:#000
    style S3_CURS fill:#DCFCE7,stroke:#166534,color:#000
    style S3_RESULT fill:#FEE2E2,stroke:#991B1B,color:#000
    style S3_VERDICT fill:#EF4444,stroke:#991B1B,color:#FFF

    style S1_TITLE fill:#EDE9FE,stroke:#5B21B6,color:#000
    style S2_TITLE fill:#EDE9FE,stroke:#5B21B6,color:#000
    style S3_TITLE fill:#EDE9FE,stroke:#5B21B6,color:#000
```

The failure analysis summarized:

| Scenario | Done-Ledger | Findings | Cursor | Outcome | Severity |
|:---------|:------------|:---------|:-------|:--------|:---------|
| 1 | OK | FAIL | FAIL | Items marked done but findings lost | **FALSE NEGATIVES** (worst case) |
| 2 | FAIL | OK | FAIL | Duplicates on re-scan | Acceptable (idempotent dedup) |
| 3 | FAIL | FAIL | OK | Page skipped on resume | **FALSE NEGATIVES** (worst case) |
| Atomic | All or none | All or none | All or none | Consistent state guaranteed | **Safe** |

False negatives are the worst possible failure for a secret scanner. A false
positive (duplicate finding) wastes human time but is ultimately harmless. A
false negative means a leaked secret goes undetected. The atomic commit exists
specifically to make false negatives from partial writes impossible.

---

## 3. Runtime vs. Typestate Comparison

The typestate pattern is not the only way to prevent invalid state transitions.
A simpler approach is to store the state in an enum field and check it at
runtime. But runtime checks have a fatal flaw: they only catch bugs that are
exercised in tests. If a code path that calls `commit()` on an unsealed
`PageCommit` is never tested, the bug ships to production and manifests as a
runtime panic (or worse, silent data corruption if the check is missing).

The typestate approach shifts enforcement to the compiler. The invalid call is
not a runtime panic -- it is a **compile error**. The code physically cannot be
written, tested, or shipped. This is a strictly stronger guarantee at zero
runtime cost.

```mermaid
%% Diagram: runtime-vs-typestate-comparison
graph LR
    subgraph runtime ["Runtime Approach (Fragile)"]
        direction TB

        R_CREATE["PageCommit::new()<br/>state = Accumulating"]
        R_ADD["add_finding()<br/>state == Accumulating? OK"]
        R_COMMIT["commit()<br/>state == Sealed?"]
        R_PANIC["RUNTIME PANIC!<br/>'Cannot commit from<br/>Accumulating state'"]
        R_PROD["Bug reaches production<br/>if untested path"]

        R_CREATE --> R_ADD
        R_ADD --> R_COMMIT
        R_COMMIT -->|"state != Sealed"| R_PANIC
        R_PANIC --> R_PROD
    end

    subgraph typestate ["Typestate Approach (Sound)"]
        direction TB

        T_CREATE["PageCommit::< Accumulating >::new()"]
        T_ADD["add_finding()<br/>impl PageCommit< Accumulating >"]
        T_COMMIT["commit()"]
        T_ERROR["COMPILE ERROR!<br/>'no method named commit<br/>found for PageCommit< Accumulating >'"]
        T_SAFE["Bug caught at compile time<br/>never reaches production"]

        T_CREATE --> T_ADD
        T_ADD -.-> T_COMMIT
        T_COMMIT -.-> T_ERROR
        T_ERROR --> T_SAFE
    end

    style R_CREATE fill:#EDE9FE,stroke:#5B21B6,color:#000
    style R_ADD fill:#EDE9FE,stroke:#5B21B6,color:#000
    style R_COMMIT fill:#EDE9FE,stroke:#5B21B6,color:#000
    style R_PANIC fill:#EF4444,stroke:#991B1B,color:#FFF
    style R_PROD fill:#FEE2E2,stroke:#991B1B,color:#000

    style T_CREATE fill:#EDE9FE,stroke:#5B21B6,color:#000
    style T_ADD fill:#EDE9FE,stroke:#5B21B6,color:#000
    style T_COMMIT fill:#F3F4F6,stroke:#374151,color:#6B7280
    style T_ERROR fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style T_SAFE fill:#8B5CF6,stroke:#5B21B6,color:#FFF
```

The comparison distills to a single principle: **errors that are structurally
impossible are better than errors that are dynamically caught.** The runtime
approach relies on discipline -- every caller must remember to seal before
committing, and every test suite must exercise the forgotten-seal path. The
typestate approach relies on the compiler -- the forgotten-seal path cannot
compile, so it cannot exist in the binary.

The dashed lines in the typestate flow represent code that **cannot be written**.
There is no `commit()` method on `PageCommit<Accumulating>`. The compiler
rejects it with a type error, not a runtime check. This is the fundamental
difference: runtime safety is probabilistic (depends on test coverage), typestate
safety is total (enforced for all possible programs).

---

## 4. Full Commit Flow

The complete lifecycle of a page commit involves four participants: the
**Worker** (scanning items), the **PageCommit** instance (tracking state), the
**DoneLedger** (recording which items have been processed), and the
**FindingsSink** (receiving discovered secrets). The **Coordinator** is notified
after the commit succeeds so it can advance the shard's cursor.

The critical section is the atomic transaction inside `commit()`. The three
writes -- marking items done, writing findings, and acknowledging the
transaction -- must all succeed or all fail. This is where the partial-write
failure scenarios from Diagram 2 are prevented.

```mermaid
%% Diagram: full-commit-flow
sequenceDiagram
    autonumber
    participant W as Worker
    participant PC as PageCommit
    participant DL as DoneLedger
    participant FS as FindingsSink
    participant CO as Coordinator

    W->>PC: new(next_cursor)
    Note over PC: State: PageCommit< Accumulating >

    rect rgb(237, 233, 254)
        Note over W,PC: Loop: for each item in page
        W->>PC: add_finding(finding_record)
        W->>PC: add_done_key(done_ledger_key)
        Note over PC: Accumulating findings<br/>and done-keys
    end

    W->>PC: seal()
    Note over PC: State: PageCommit< Sealed ><br/>No more additions possible

    W->>PC: commit(done_ledger, findings_sink)

    rect rgb(237, 233, 254)
        Note over PC,FS: Atomic Transaction Boundary
        PC->>DL: begin_transaction()
        PC->>DL: mark_done(keys[])
        DL-->>PC: Ok
        PC->>FS: write_findings(findings[])
        FS-->>PC: Ok
        PC->>DL: commit_transaction()
        DL-->>PC: Ok
        Note over PC: All 3 writes succeeded atomically
    end

    PC-->>W: PageCommit< Committed >
    Note over PC: State: PageCommit< Committed ><br/>Results extractable

    W->>PC: next_cursor()
    PC-->>W: cursor_value

    W->>CO: checkpoint(shard_id, token, cursor_value)
    CO-->>W: Ok
```

The sequence breaks down into five phases:

1. **Construction** (step 1): The worker creates a `PageCommit<Accumulating>`
   with the cursor value it will advance to after the commit succeeds. The
   cursor is stored inside the PageCommit but is not sent to the coordinator
   until the commit is confirmed.

2. **Accumulation** (steps 2-3): The worker iterates over items in the page.
   For each item, it may call `add_finding()` (if a secret was detected) and
   `add_done_key()` (always, to mark the item as processed). These methods are
   only available on `PageCommit<Accumulating>`.

3. **Sealing** (step 4): The worker calls `seal()`, which consumes the
   `PageCommit<Accumulating>` and returns a `PageCommit<Sealed>`. After this
   point, no more findings or done-keys can be added. The seal is a one-way
   gate.

4. **Atomic commit** (steps 5-11): The worker calls `commit()` on the sealed
   PageCommit, passing references to the DoneLedger and FindingsSink. Inside
   `commit()`, a transaction is opened, done-keys are marked, findings are
   written, and the transaction is committed. If any step fails, the transaction
   is rolled back and no state changes are persisted. On success, the method
   returns `PageCommit<Committed>`.

5. **Cursor advancement** (steps 12-14): The worker extracts `next_cursor()`
   from the committed PageCommit and sends it to the Coordinator via
   `checkpoint()`. This is the only point at which the coordinator learns
   that the page has been processed. Because the cursor is only advanced after
   the atomic commit succeeds, partial writes cannot cause the coordinator to
   skip a page.

The transaction boundary (the inner `rect` block in the sequence diagram) is the
heart of the protocol. Everything outside that boundary is type-system
enforcement (preventing invalid method calls). Everything inside it is
persistence enforcement (preventing partial writes). Together, they provide
end-to-end safety: you cannot commit without sealing, and you cannot partially
commit.

---

## Cross-References

- [Shard and Run State Machines](05-shard-and-run-state-machines.md) -- the
  shard lifecycle that the cursor advancement feeds into
- [Fencing Protocol](06-fencing-protocol.md) -- the `checkpoint` call in
  step 14 passes through the 5-check fencing preamble
- [System Overview](01-system-overview.md) -- where PageCommit fits in the
  overall architecture

## Source Code References

- **Deep dive document**: `07-boundary-5-persistence/04-commit-protocol-typestate.md`
- **Persistence contracts**: `crates/gossip-contracts/src/persistence/`
- **Typestate markers**: `crates/gossip-contracts/src/persistence/`
- **Done-ledger interface**: `crates/gossip-contracts/src/persistence/`
- **Findings sink interface**: `crates/gossip-contracts/src/persistence/`
