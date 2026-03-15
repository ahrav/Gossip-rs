# System Overview

This document describes the high-level architecture of Gossip-rs, a distributed
secret scanner designed around five clearly delineated boundaries. The
five-boundary model is the load-bearing architectural decision of the entire
system: every module, every crate, and every runtime interaction can be traced
back to one of these boundaries. Understanding them is the single fastest way to
build a mental model of the codebase.

The boundaries enforce an acyclic dependency rule. B1 (Identity) sits at the
foundation and depends on nothing. Every other boundary depends on B1, and the
remaining edges form a strict DAG. This means you can reason about any boundary
in isolation by knowing only the boundaries beneath it, and you can compile lower
layers without touching higher ones.

---

## Five-Boundary Architecture

The diagram below shows the five boundaries, their core responsibilities, and
how they depend on one another. The arrows are labeled with the key types that
flow across each dependency edge. Notice that B1 is the root of the DAG: it
provides the deterministic identity types that every other boundary consumes.

B3 (Shard Algebra) also lives at a low level -- it depends only on B1 -- because
shard definitions are pure data that must be shared between coordination,
connectors, and persistence without creating cycles. B2 (Coordination) sits
above both B1 and B3: it uses identity types to fence ownership and shard
definitions to assign work. B4 (Connector) is the I/O surface that talks to
external data sources; it depends on B1 for stable item identity and B3 for
shard ranges. B5 (Persistence) depends on B1 for content-addressed keys and on
B2 for fencing tokens that guard writes.

This layering means that the pure-logic core (B1 + B3) can be tested with zero
I/O, coordination logic (B2) can be tested with in-memory shard maps, and the
I/O boundaries (B4, B5) can be swapped or mocked independently.

```mermaid
%% Diagram: five-boundary-architecture
graph TD
    B1["<b>B1: Identity</b><br/>Deterministic hashing &amp; ID derivation"]
    B3["<b>B3: Shard Algebra</b><br/>Shard splitting, merging &amp; range math"]
    B2["<b>B2: Coordination</b><br/>Lease management &amp; shard assignment"]
    B4["<b>B4: Connector</b><br/>External data-source enumeration &amp; fetch"]
    B5["<b>B5: Persistence</b><br/>Done-ledger, cursor &amp; finding storage"]

    B3 -->|"ShardId, ShardSpec"| B1
    B2 -->|"FenceEpoch, WorkerId"| B1
    B2 -->|"ShardSpec"| B3
    B4 -->|"StableItemId"| B1
    B4 -->|"ShardSpec"| B3
    B5 -->|"FindingId, StableItemId"| B1
    B5 -->|"FenceEpoch"| B2

    style B1 fill:#DBEAFE,stroke:#1E40AF,stroke-width:2px,color:#1E40AF
    style B2 fill:#DCFCE7,stroke:#166534,stroke-width:2px,color:#166534
    style B3 fill:#FFF7ED,stroke:#9A3412,stroke-width:2px,color:#9A3412
    style B4 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style B5 fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
```

---

## Crate Mapping

The crate structure mirrors the boundary structure deliberately. Each crate owns
exactly the code for one or two boundaries, and the Cargo dependency graph
reproduces the boundary DAG above. This gives us compilation isolation: a change
to connector logic does not force a rebuild of coordination, and a change to
identity hashing does not force a rebuild of persistence until the contracts
crate version is bumped.

`gossip-contracts` is the foundation crate. It contains both B1 (Identity) and
B3 (Shard Algebra) because these two boundaries are pure contracts -- no I/O, no
async runtime, no platform dependencies. Keeping them together in one crate
avoids a circular dependency that would arise if shard algebra needed identity
types and vice versa. Every other crate depends on `gossip-contracts`.

`gossip-coordination` owns B2, `gossip-connectors` owns B4, and persistence
contracts live within `gossip-contracts/src/persistence/`. Detection is owned by
`scanner-engine`, with `scanner-scheduler` providing the filesystem execution
engine and `scanner-git` handling git-specific scanning. `gossip-scanner-runtime`
imports the source-family vocabulary from `gossip-contracts` and exposes the
runtime entrypoints that select ordered-content or git-repo family modules for
both the `scanner-rs` CLI binary and the `gossip-worker` binary.

`gossip-coordination-etcd` provides an etcd-backed coordination backend.
`gossip-persistence-inmemory` provides in-memory persistence backends for testing
and conformance. `gossip-pg-common` holds shared PostgreSQL primitives (migration
runner, `u64 ↔ BIGINT` encoding, test-support lifecycle) used by both PostgreSQL
persistence backends. `gossip-done-ledger-postgres` and
`gossip-findings-postgres` implement the `DoneLedger` and `FindingsSink` traits
against PostgreSQL.

```mermaid
%% Diagram: crate-mapping
graph LR
    subgraph Boundaries
        B1["B1: Identity"]
        B3["B3: Shard Algebra"]
        B2["B2: Coordination"]
        B4["B4: Connector"]
        B5["B5: Persistence"]
    end

    subgraph Crates
        contracts["gossip-contracts"]
        stdx["gossip-stdx"]
        frontier["gossip-frontier"]
        coordination["gossip-coordination"]
        coordination_etcd["gossip-coordination-etcd"]
        connectors["gossip-connectors"]
        scanner_engine["scanner-engine"]
        scanner_scheduler["scanner-scheduler"]
        scanner_git["scanner-git"]
        persistence_inmem["gossip-persistence-inmemory"]
        pg_common["gossip-pg-common"]
        done_ledger_pg["gossip-done-ledger-postgres"]
        findings_pg["gossip-findings-postgres"]
        runtime["gossip-scanner-runtime"]
        worker["gossip-worker"]
        cli["scanner-rs-cli"]
        integration_tests["scanner-engine-integration-tests"]
    end

    B1 -->|"contains"| contracts
    B3 -->|"contains"| contracts
    B3 -->|"contains"| frontier
    B5 -->|"persistence contracts"| contracts
    B5 -->|"persistence impl"| persistence_inmem
    B5 -->|"PostgreSQL shared"| pg_common
    B5 -->|"done-ledger backend"| done_ledger_pg
    B5 -->|"findings backend"| findings_pg
    B2 -->|"contains"| coordination
    B4 -->|"contains"| connectors

    frontier -->|"depends on"| contracts
    frontier -->|"depends on"| stdx
    coordination -->|"depends on"| contracts
    coordination -->|"depends on"| stdx
    connectors -->|"depends on"| contracts
    scanner_git -->|"depends on"| scanner_engine
    runtime -->|"depends on"| contracts
    runtime -->|"depends on"| scanner_engine
    runtime -->|"depends on"| scanner_scheduler
    runtime -->|"depends on"| scanner_git
    worker -->|"depends on"| runtime
    cli -->|"depends on"| runtime

    coordination_etcd -->|"depends on"| coordination
    persistence_inmem -->|"depends on"| contracts
    pg_common -->|"depends on"| contracts
    done_ledger_pg -->|"depends on"| contracts
    done_ledger_pg -->|"depends on"| pg_common
    findings_pg -->|"depends on"| contracts
    findings_pg -->|"depends on"| pg_common
    integration_tests -->|"depends on"| scanner_engine

    style B1 fill:#DBEAFE,stroke:#1E40AF,stroke-width:2px,color:#1E40AF
    style B3 fill:#FFF7ED,stroke:#9A3412,stroke-width:2px,color:#9A3412
    style B2 fill:#DCFCE7,stroke:#166534,stroke-width:2px,color:#166534
    style B4 fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style B5 fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6

    style contracts fill:#DBEAFE,stroke:#1E40AF,stroke-width:2px,color:#1E40AF
    style stdx fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style frontier fill:#FFF7ED,stroke:#9A3412,stroke-width:2px,color:#9A3412
    style coordination fill:#DCFCE7,stroke:#166534,stroke-width:2px,color:#166534
    style connectors fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style scanner_engine fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style scanner_scheduler fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style scanner_git fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style runtime fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style worker fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style cli fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style coordination_etcd fill:#DCFCE7,stroke:#166534,stroke-width:2px,color:#166534
    style persistence_inmem fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style pg_common fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style done_ledger_pg fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style findings_pg fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style integration_tests fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
```

---

## Simplified Scan Flow

The sequence diagram below traces a single shard through one complete scan
cycle. This is the core workflow that every deployment executes thousands of
times per minute, and it shows how the five boundaries compose at runtime to
deliver exactly-once scanning semantics.

The flow begins with B2 (Coordination) assigning a shard to a worker along with
a fencing token. The fencing token is critical: it is a monotonically increasing
value that the persistence layer checks on every write. If a worker loses its
lease and a new worker takes over the same shard, the old worker's fencing token
becomes stale and its writes are rejected. This is how the system prevents
duplicate processing without distributed locks.

The acquire response also carries a `CapacityHint` -- an advisory count of
remaining available shards and the earliest lease deadline -- so workers can
make backoff/retry decisions without additional RPCs (see
[07-lease-lifecycle.md](07-lease-lifecycle.md) Diagram 5).

Once the worker has a shard assignment, it uses B4 (Connector) to enumerate
items from the external data source -- a Git repository, an S3 bucket, a
Confluence space, or any other supported source. Each `ScanItem` carries a
`StableItemId` and `VersionId` produced by the connector through B1 (Identity).
The worker derives an `OvidHash` from these two fields and checks the
done-ledger in B5 (Persistence) to skip items that have already been scanned.
For new items, the worker runs the detection engine, derives a `FindingId` for
each discovered secret, and commits the entire page -- findings, done-ledger
updates, and cursor position -- through the receipt-chained typestate protocol
in B5. Finally, the worker reports shard completion back to B2.

The atomicity of the page commit is what guarantees exactly-once semantics: if
the worker crashes mid-page, the cursor has not advanced, and the next worker
replays from the last saved cursor. The `PageCommit<S>` typestate enforces the
durability ordering -- findings before done-ledger before checkpoint -- at
compile time.

```mermaid
%% Diagram: simplified-scan-flow
sequenceDiagram
    participant C as Coordinator (B2)
    participant W as Worker
    participant Conn as Connector (B4)
    participant Id as Identity (B1)
    participant P as Persistence (B5)

    C->>W: assign shard + fencing token
    activate W

    W->>Conn: enumerate items in shard range
    Conn-->>W: stream of raw items

    loop For each item
        W->>Id: derive OvidHash(StableItemId, VersionId)
        Id-->>W: OvidHash

        W->>P: check done-ledger(OvidHash)
        P-->>W: seen / not-seen

        alt not seen
            W->>W: run detection engine
            W->>Id: derive FindingId(secret)
            Id-->>W: FindingId
        end
    end

    W->>P: commit page (findings + done-ledger + cursor)
    P-->>W: ack (fencing token validated)

    W->>C: mark shard complete
    deactivate W
```

---

## Build DAG

The crate graph compiles in four tiers. Tier 0 (`gossip-stdx`, `gossip-contracts`,
and `gossip-frontier`) has no dependencies on higher-level crates and compiles
first. `gossip-stdx` is a foundational utility crate depended on by contracts,
frontier, and coordination. Tier 1 includes `gossip-coordination`,
`gossip-connectors`, `gossip-persistence-inmemory`, `gossip-pg-common`,
`gossip-done-ledger-postgres`, `gossip-findings-postgres`,
`scanner-engine`, `scanner-scheduler`, and `scanner-git` --
these compile in parallel once Tier 0 finishes. The three PostgreSQL crates
(`gossip-pg-common`, `gossip-done-ledger-postgres`, `gossip-findings-postgres`)
depend only on `gossip-contracts` (and `gossip-pg-common` for the two backends),
placing them alongside other Tier 1 crates. Tier 2 includes
`gossip-coordination-etcd` and `gossip-scanner-runtime`, which depend on Tier 1
crates. Tier 3
(`gossip-worker`, `scanner-rs-cli`, `scanner-engine-integration-tests`) are the
final binaries and test crates.

```mermaid
%% Diagram: build-dag
graph TD
    subgraph "Tier 0"
        stdx["gossip-stdx"]
        contracts["gossip-contracts"]
        frontier["gossip-frontier"]
    end

    subgraph "Tier 1"
        coordination["gossip-coordination"]
        connectors["gossip-connectors"]
        persistence_inmem["gossip-persistence-inmemory"]
        pg_common["gossip-pg-common"]
        done_ledger_pg["gossip-done-ledger-postgres"]
        findings_pg["gossip-findings-postgres"]
        scanner_engine["scanner-engine"]
        scanner_scheduler["scanner-scheduler"]
        scanner_git["scanner-git"]
    end

    subgraph "Tier 2"
        coordination_etcd["gossip-coordination-etcd"]
        runtime["gossip-scanner-runtime"]
    end

    subgraph "Tier 3"
        worker["gossip-worker"]
        cli["scanner-rs-cli"]
        integration_tests["scanner-engine-integration-tests"]
    end

    stdx --> contracts
    stdx --> frontier
    stdx --> coordination
    stdx --> scanner_engine
    contracts --> frontier
    contracts --> coordination
    contracts --> connectors
    contracts --> persistence_inmem
    contracts --> pg_common
    contracts --> done_ledger_pg
    contracts --> findings_pg
    pg_common --> done_ledger_pg
    pg_common --> findings_pg
    coordination --> coordination_etcd
    scanner_engine --> scanner_git
    contracts --> runtime
    scanner_engine --> runtime
    scanner_scheduler --> runtime
    scanner_git --> runtime
    runtime --> worker
    runtime --> cli
    scanner_engine --> integration_tests

    style stdx fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style contracts fill:#DBEAFE,stroke:#1E40AF,stroke-width:2px,color:#1E40AF
    style frontier fill:#FFF7ED,stroke:#9A3412,stroke-width:2px,color:#9A3412
    style coordination fill:#DCFCE7,stroke:#166534,stroke-width:2px,color:#166534
    style connectors fill:#FEE2E2,stroke:#991B1B,stroke-width:2px,color:#991B1B
    style scanner_engine fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style scanner_scheduler fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style scanner_git fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style runtime fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style worker fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style cli fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
    style coordination_etcd fill:#DCFCE7,stroke:#166534,stroke-width:2px,color:#166534
    style persistence_inmem fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style pg_common fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style done_ledger_pg fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style findings_pg fill:#EDE9FE,stroke:#5B21B6,stroke-width:2px,color:#5B21B6
    style integration_tests fill:#F3F4F6,stroke:#374151,stroke-width:2px,color:#374151
```

For the full type-annotated dependency DAG and tiered compilation analysis, see [Boundary Dependency Graph](02-boundary-dependency-graph.md).

---

## Cross-References

| Topic                       | Diagram File                                                             |
| --------------------------- | ------------------------------------------------------------------------ |
| Identity boundary deep-dive | [03-id-derivation-dag.md](03-id-derivation-dag.md)                       |
| Shard algebra deep-dive     | [13-shard-algebra-types.md](13-shard-algebra-types.md)                   |
| Shard algebra operations    | [12-split-operations.md](12-split-operations.md)                         |
| Coordination protocol       | [05-shard-and-run-state-machines.md](05-shard-and-run-state-machines.md) |
| Connector lifecycle         | [09-circuit-breaker.md](09-circuit-breaker.md)                           |
| Persistence guarantees      | [08-pagecommit-typestate.md](08-pagecommit-typestate.md)                 |

## Source Code References

| Boundary           | Primary Source                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| B1: Identity       | `crates/gossip-contracts/src/identity/`                                                                                              |
| B3: Shard Algebra  | `crates/gossip-contracts/src/coordination/shard_spec.rs` (data model) + `crates/gossip-frontier/src/` (key encoding, hints, builder) |
| Shared utilities   | `crates/gossip-stdx/`                                                                                                                |
| B2: Coordination   | `crates/gossip-contracts/src/coordination/` (data types) + `crates/gossip-coordination/src/` (protocol)                              |
| B4: Connector      | `crates/gossip-contracts/src/connector/` + `crates/gossip-connectors/`                                                               |
| B5: Persistence    | `crates/gossip-contracts/src/persistence/`                                                                                           |
| B5: Persistence (PostgreSQL shared) | `crates/gossip-pg-common/`                                                                                              |
| B5: Persistence (done-ledger PG)    | `crates/gossip-done-ledger-postgres/`                                                                                   |
| B5: Persistence (findings PG)       | `crates/gossip-findings-postgres/`                                                                                      |
| Detection engine   | `crates/scanner-engine/`                                                                                                             |
| Runtime family modules | `crates/gossip-scanner-runtime/src/{ordered_content.rs, git_repo.rs, distributed.rs}`                                          |
| Scanner runtime    | `crates/gossip-scanner-runtime/`                                                                                                     |
| Worker binary      | `crates/gossip-worker/`                                                                                                              |
| CLI binary         | `crates/scanner-rs-cli/`                                                                                                             |
| B2: Coordination (etcd) | `crates/gossip-coordination-etcd/`                                                                                              |
| B5: Persistence (in-mem) | `crates/gossip-persistence-inmemory/`                                                                                           |
| Integration tests        | `crates/scanner-engine-integration-tests/`                                                                                      |
