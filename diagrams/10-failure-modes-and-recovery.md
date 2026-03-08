# Failure Modes and Recovery

Distributed systems fail in countless ways. Networks partition, processes crash,
disks fill, clocks drift, and external services disappear without warning. A
system that only works on the happy path is not a system -- it is a prototype.
This chapter catalogs the primary failure modes in Gossip-rs and traces the
recovery path for each one, demonstrating that the architecture handles every
cataloged failure with a defined, tested response.

The system's failure philosophy rests on five principles:

1. **Fail Fast.** Detect failures as close to the source as possible. Do not
   allow corrupt state to propagate through the pipeline. Fencing tokens reject
   stale writers immediately; circuit breakers trip after a small number of
   failures rather than letting timeouts accumulate.

2. **Fail Safe.** When in doubt, stop and let someone else try. A worker that
   cannot reach the coordinator parks its shard and yields. A coordinator that
   restarts rebuilds from persistent state rather than guessing.

3. **Fail Visibly.** Every failure produces a typed error, a log entry, or both.
   Silent failures -- where work is lost but nobody notices -- are the most
   dangerous class of bug. The op-log, fencing protocol, and done-ledger
   collectively ensure that lost work is detected and retried.

4. **Recover Automatically.** The system should heal without human intervention
   whenever possible. Lease expiry reclaims crashed workers' shards. Circuit
   breaker cooldowns probe recovering sources. Cursor-based replay resumes from
   the last committed position.

5. **Minimize Blast Radius.** A failure in one connector should not affect other
   connectors. A crashed worker should not stall the entire run. A network
   partition between one worker and the coordinator should not prevent other
   workers from making progress.

The overriding design choice is that **safety takes priority over liveness**.
The system will tolerate brief periods of unavailability -- a shard sitting idle
while a lease expires, a source unreachable while a circuit breaker cools down --
but it will never tolerate data loss or data corruption. An uncommitted page can
be re-processed; a corrupted cursor or a double-counted finding cannot be
un-corrupted.

---

## Diagram 1: Worker Crash Recovery

The most common failure mode is a worker crashing mid-page. The worker may have
enumerated items, derived identities, and accumulated findings -- but if it
crashes before the atomic commit (Step 9 in the scan flow), all that in-flight
work is lost. This is acceptable by design: the cursor has not advanced, so the
next worker to claim the shard will re-process the same page from the last
committed position.

The recovery sequence relies on three mechanisms working together: lease expiry
detects the crash, the fencing token prevents the crashed worker from interfering
if it restarts, and cursor atomicity ensures exactly-once semantics for committed
pages.

```mermaid
%% Diagram: worker-crash-recovery
sequenceDiagram
    autonumber
    participant W1 as Worker 1 (crashes)
    participant CO as Coordinator (B2)
    participant W2 as Worker 2 (new)

    Note over W1,CO: Normal operation
    W1->>CO: acquire_and_restore_into(shard_1)
    CO-->>W1: Ok(token=5, cursor=page_3)
    W1->>W1: enumerate page_3, scan items,<br/>accumulate findings...

    Note over W1: Worker 1 CRASHES mid-page
    W1--xW1: Process killed

    rect rgb(254, 226, 226)
        Note over W1,CO: Uncommitted findings lost.<br/>Cursor NOT advanced past page_3.
    end

    Note over CO: Time passes...

    CO->>CO: Lease timer expires (TTL exceeded)
    CO->>CO: Release shard_1 lease (Active, unleased)

    Note over CO,W2: New worker picks up the shard
    W2->>CO: acquire_and_restore_into(shard_1)
    CO-->>W2: Ok(token=6, last_committed_cursor=page_3)

    Note over W2: Worker 2 resumes from page_3<br/>(the last COMMITTED cursor)
    W2->>W2: Re-processes interrupted page from page_3
    W2->>CO: checkpoint(shard_1, token=6, cursor=page_4)
    CO-->>W2: Ok(cursor advanced to page_4)

    rect rgb(220, 252, 231)
        Note over W1,W2: At most one page of work repeated.<br/>No data loss. No duplicates.
    end

    Note over W1,CO: Meanwhile, if Worker 1 restarts...
    W1-->>CO: checkpoint(shard_1, token=5, cursor=page_4)
    CO--xW1: Err(StaleFence: token 5 != 6)
    Note over W1: Stale token rejected.<br/>Worker 1 stops.
```

The critical property is **cursor atomicity**: the cursor only advances inside
the receipt-chained commit boundary. If the commit did not reach
`CheckpointDurable`, the cursor did not advance. This means the next worker
always starts from a consistent position.
The fencing token (incrementing from 5 to 6 on the new acquisition) ensures that
Worker 1 cannot interfere even if it comes back to life -- its stale token is
rejected immediately by the 5-check validation preamble (INV-S12).

---

## Diagram 2: Coordinator Crash Recovery

The coordinator is the central authority for shard ownership, lease management,
and run lifecycle. When it crashes, the impact depends entirely on the storage
backend. Gossip-rs supports two backend modes -- in-memory and persistent -- with
dramatically different recovery characteristics.

With an in-memory backend, all coordination state lives in the coordinator's
process memory. A crash destroys everything: run manifests, shard records, lease
tables, cursors. The run must restart from scratch. This is acceptable for
development and testing but unsuitable for production.

With a persistent backend, the coordinator is effectively stateless. All
coordination state lives in the database. The coordinator can crash, restart,
reconnect to the database, and rebuild its entire in-memory view. Workers
experience a brief period of unavailability (lease operations time out during
the restart window), but no data is lost and no work is duplicated.

```mermaid
%% Diagram: coordinator-crash-recovery
sequenceDiagram
    autonumber
    participant CO as Coordinator (B2)
    participant DB as Persistent Backend (B5)
    participant W as Worker

    rect rgb(254, 226, 226)
        Note over CO: Scenario A: InMemory Backend
        CO--xCO: Coordinator CRASHES
        Note over CO,DB: ALL state lost.<br/>Run manifests, shard records,<br/>leases, cursors — gone.
        Note over CO: Must restart entire run from scratch.
        Note over CO,W: Acceptable for dev/test ONLY.
    end

    Note over CO,W: ════════════════════════════════

    rect rgb(220, 252, 231)
        Note over CO: Scenario B: Persistent Backend

        CO--xCO: Coordinator CRASHES

        Note over W: Workers detect timeout.<br/>Lease operations fail.<br/>Workers wait and retry.

        CO->>CO: Coordinator restarts
        CO->>DB: Load all active runs
        DB-->>CO: Run manifests + shard records

        CO->>DB: Find expired leases (TTL exceeded during downtime)
        DB-->>CO: List of expired leases

        CO->>DB: Release expired leases → shards become Active (unleased)
        DB-->>CO: Ok

        Note over CO: Coordination state fully rebuilt.

        W->>CO: acquire_and_restore_into(shard_1)
        CO-->>W: Ok(token=N+1, last_committed_cursor)

        Note over W: Worker resumes scanning<br/>from last committed cursor.

        Note over CO,W: No data loss.<br/>Brief unavailability during restart.<br/>All state reconstructed from DB.
    end
```

The persistent backend transforms the coordinator from a stateful singleton into
a stateless service that can be restarted, migrated, or even replaced without
losing any scan progress. The key insight is that all durable state -- shard
records, cursors, lease metadata -- lives in the database. The coordinator's
in-memory state is a cache that can be rebuilt from the persistent store at any
time.

During the restart window, workers will experience timeouts on lease operations.
This is by design: the system prefers a brief pause over any risk of
inconsistency. Once the coordinator is back, it releases any leases that expired
during downtime (the original holders may have crashed or moved on), and workers
can acquire shards again with fresh fencing tokens.

---

## Diagram 3: Network Partition -- Worker to Coordinator

A network partition between a worker and the coordinator is one of the most
subtle failure modes. The worker may still be able to reach the data source (via
the connector), so it can continue reading items and accumulating findings. But
it cannot commit those findings because the commit operation requires
coordinator involvement (cursor advancement, fencing token validation). The
worker is forced to stop and wait.

Meanwhile, the coordinator sees the worker's lease expire and makes the shard
available for other workers. When the partition heals, the original worker
discovers that its lease is gone (fencing token is stale) and must re-acquire
the shard to continue.

```mermaid
%% Diagram: network-partition-worker-coordinator
sequenceDiagram
    autonumber
    participant W as Worker
    participant CO as Coordinator (B2)
    participant CN as Connector (B4)

    W->>CO: acquire_and_restore_into(shard_1)
    CO-->>W: Ok(token=5, cursor=page_3)

    W->>CN: enumerate(page_3)
    CN-->>W: Page(items[], next_cursor)

    rect rgb(254, 226, 226)
        Note over W,CO: ═══ NETWORK PARTITION ═══<br/>Worker cannot reach Coordinator

        Note over CO: Coordinator side:<br/>Lease timer expires for Worker.
        CO->>CO: Release shard_1 lease (Active, unleased)

        Note over W,CN: Worker side:<br/>Can still reach data source.
        W->>CN: read_item(item_key)
        CN-->>W: content
        W->>W: scan(content) → findings[]
        W->>W: Accumulate findings in memory

        W--xCO: commit(token=5, cursor=page_4) → TIMEOUT
        Note over W: Commit fails. Cannot advance cursor.

        W->>W: Park shard locally.<br/>Wait for network recovery.
    end

    Note over W,CO: ═══ PARTITION HEALS ═══

    W->>CO: acquire_and_restore_into(shard_1)
    Note over CO: Worker's old lease already expired.<br/>Grant new lease.
    CO-->>W: Ok(token=6, last_committed_cursor=page_3)

    Note over W: Discard in-memory findings (stale).<br/>Resume from page_3 with token=6.
    W->>CN: enumerate(page_3)
    CN-->>W: Page(items[], next_cursor)
    W->>W: Re-scan, accumulate findings
    W->>CO: commit(token=6, cursor=page_4, findings)
    CO-->>W: Ok(cursor advanced)

    rect rgb(220, 252, 231)
        Note over W,CO: Fencing token prevents split-brain.<br/>Only token=6 is valid now.<br/>Any stale token=5 operations are rejected.
    end
```

The partition scenario reveals why fencing tokens are essential. Without them,
two workers could simultaneously believe they own the same shard -- the original
worker (still running, unable to reach the coordinator) and a new worker that
acquired the shard after the lease expired. The fencing token resolves this
ambiguity: only the holder of the highest token can commit mutations. The
original worker's token (5) is permanently stale once token 6 is issued.

The worker discards its in-memory findings after the partition heals because
those findings were accumulated under a stale lease. While the findings
themselves might be correct, the system cannot verify this without re-running the
full pipeline from the committed cursor. Re-processing one page is a small cost
compared to the risk of inconsistency.

---

## Diagram 4: Network Partition -- Worker to Source

When the failure is between the worker and the external data source (GitHub, S3,
etc.) rather than between the worker and the coordinator, the retry-budget
pattern contains the damage. The scan loop uses a `RetryBudget` that classifies
errors via `BackendError` into `RetryableReason` and `PermanentReason` categories.
After the retry budget is exhausted, the shard is parked with
`ParkReason::TooManyErrors`, freeing the worker for other shards.

> **Note:** The sequence diagram below shows a **target design** where a full
> circuit breaker state machine (Closed/Open/HalfOpen) mediates connector calls.
> The current implementation uses a `RetryBudget` with `BackendError` classification
> in `scanner-scheduler/src/scheduler/failure.rs`. The parking outcome (`ParkReason::TooManyErrors`) is the same;
> the intermediate states (Open, HalfOpen, probe) are aspirational.

The worker responds by parking the shard with a `ParkReason::TooManyErrors`
designation and moving on to other available work.

```mermaid
%% Diagram: network-partition-worker-source
sequenceDiagram
    autonumber
    participant W as Worker
    participant CB as Circuit Breaker (B4)
    participant SRC as Source (GitHub)

    W->>CB: enumerate(shard_range, cursor)
    CB->>SRC: GET /repos/org/repo/contents
    SRC-->>CB: 200 OK (items)
    CB-->>W: Page(items[], next_cursor)

    Note over W,SRC: Source becomes unreachable

    W->>CB: enumerate(next_page)
    CB->>SRC: GET /repos/org/repo/contents
    SRC--xCB: Connection timeout
    CB->>CB: failure_count = 1
    CB-->>W: Err(Timeout)

    W->>CB: enumerate(next_page) [retry]
    CB->>SRC: GET /repos/org/repo/contents
    SRC--xCB: Connection timeout
    CB->>CB: failure_count = 2
    CB-->>W: Err(Timeout)

    W->>CB: enumerate(next_page) [retry]
    CB->>SRC: GET /repos/org/repo/contents
    SRC--xCB: Connection timeout
    CB->>CB: failure_count = 3 → THRESHOLD EXCEEDED
    Note over CB: Circuit Breaker OPENS
    CB-->>W: Err(Timeout)

    rect rgb(254, 226, 226)
        W->>CB: enumerate(next_page)
        CB--xW: Err(CircuitBreakerOpen)
        Note over CB: Immediate rejection.<br/>No request sent to source.
    end

    W->>W: Park shard with<br/>ParkReason::TooManyErrors
    Note over W: Release lease. Move to other shards.

    Note over CB: Cooldown period elapses...
    CB->>CB: State → HalfOpen

    rect rgb(220, 252, 231)
        Note over W,SRC: New worker probes the source
        W->>CB: enumerate(shard_range, cursor)
        CB->>SRC: GET /repos/org/repo/contents [probe]
        SRC-->>CB: 200 OK
        CB->>CB: State → Closed
        CB-->>W: Page(items[], next_cursor)
        Note over W: Scanning resumes normally.
    end

    Note over W,SRC: Other connectors unaffected.<br/>Circuit breakers are per-source isolation.
```

The retry-budget pattern achieves two goals simultaneously. First, it
**fails fast**: once the budget is exhausted, the worker stops retrying a source
that is known to be unhealthy. Second, it **minimizes blast radius**: the budget
is scoped to a single shard's connector interaction. If GitHub is unreachable but
S3 is fine, workers can continue scanning S3 shards without interruption.

> **Note:** The target design introduces a full circuit breaker state machine
> (Closed → Open → HalfOpen) with cooldown and probe phases (shown in the
> sequence diagram above). The current implementation achieves the same parking
> outcome (`ParkReason::TooManyErrors`) via `RetryBudget` and `BackendError`
> classification, without the intermediate Open/HalfOpen states.

The parking mechanism ensures the shard is not lost. A parked shard retains its
cursor position and can be unparked (an admin operation) or picked up by a
future run. The `ParkReason` field records why the shard was parked, enabling
operators to diagnose and remediate the underlying issue.

---

## Diagram 5: Split-Brain Prevention via Fencing

Split-brain is the nightmare scenario in any distributed system: two processes
both believe they are the sole owner of a resource, and both write to it
simultaneously, producing inconsistent state. In Gossip-rs, split-brain would
mean two workers advancing the cursor on the same shard, potentially committing
overlapping or conflicting findings.

The fencing token protocol makes split-brain impossible. The monotonically
increasing token (INV-S11) combined with the stale-token rejection rule
(INV-S12) ensures that at most one writer can succeed at any point in time. A
partition may temporarily create two workers that *believe* they own the shard,
but only the one with the highest token can *write* to it.

```mermaid
%% Diagram: split-brain-prevention-fencing
sequenceDiagram
    autonumber
    participant W1 as Worker 1 (stale token=5)
    participant CO as Coordinator (B2)
    participant W2 as Worker 2 (current token=6)

    Note over W1,W2: After partition heals
    W2->>CO: commit(token=6, cursor=page_3)
    CO-->>W2: Ok (6 == 6 ✓)

    W1->>CO: commit(token=5, cursor=page_3)
    CO--xW1: Err(StaleFence: 5 != 6)

    Note over W1,W2: Single-writer invariant maintained (INV-S10)
```

> For the full sequence including partition onset, lease expiry, and shard
> re-acquisition, see
> [Fencing Protocol -- Diagram 2: Zombie Worker Resolution](06-fencing-protocol.md).

The diagram illustrates the fundamental asymmetry of the fencing protocol.
Worker 2's commit succeeds because `6 == 6` is true -- it holds the current
token and is the rightful owner. Worker 1's commit fails because `5 != 6` --
its token is stale, and no amount of retrying will make it valid again. The
only option for Worker 1 is to stop, discard its in-flight work, and
re-acquire the shard if it wants to continue (which would give it token 7).

This is not eventual consistency -- it is **immediate rejection**. There is no
window of ambiguity, no reconciliation phase, no conflict resolution. The stale
writer is told "no" on its first attempt to write, before any damage can occur.

---

## Diagram 6: Recovery Decision Tree

The following decision tree provides a diagnostic guide for operators and the
system's own recovery logic. Given a detected failure, the tree walks through
the failure type, the automatic recovery mechanism, and the expected outcome.
Most paths lead to automatic recovery with no data loss. The few paths that
require human intervention (coordinator crash with in-memory backend, data
corruption) are clearly marked.

```mermaid
%% Diagram: recovery-decision-tree
graph TD
    START(["Failure detected"])

    WHAT{"What failed?"}

    %% Worker crash path
    WC["Worker crash"]
    WC_LEASE["Lease expires<br/>(TTL timeout)"]
    WC_NEW["New worker acquires shard<br/>with fresh fencing token"]
    WC_RESUME["Resume from<br/>last committed cursor"]
    WC_OK["No data loss<br/>(at most one page repeated)"]

    %% Coordinator crash path
    CC["Coordinator crash"]
    CC_PERSIST{"Using persistent<br/>backend?"}
    CC_YES["Restart coordinator"]
    CC_REBUILD["Rebuild state from DB"]
    CC_RELEASE["Release expired leases"]
    CC_OK["No data loss<br/>(brief unavailability)"]
    CC_NO["Restart run from scratch"]
    CC_LOST["All state lost<br/>(dev/test only)"]

    %% Network partition: worker <-> coordinator
    NP_WC["Network partition<br/>(Worker ↔ Coordinator)"]
    NP_WC_LEASE["Worker lease expires<br/>from coordinator's view"]
    NP_WC_HEAL["Partition heals"]
    NP_WC_REACQ["Re-acquire with<br/>new fencing token"]
    NP_WC_OK["No data loss<br/>(stale token rejected)"]

    %% Network partition: worker <-> source
    NP_WS["Network partition<br/>(Worker ↔ Source)"]
    NP_WS_CB["Circuit breaker opens"]
    NP_WS_PARK["Park shard<br/>(TooManyErrors)"]
    NP_WS_COOL["Wait for cooldown"]
    NP_WS_PROBE["Probe source<br/>(half-open state)"]
    NP_WS_OK["Resume scanning"]

    %% Source outage
    SO["Source outage"]

    %% Data corruption
    DC["Data corruption"]
    DC_REDERIVE["Re-derive from<br/>source of truth"]
    DC_RESCAN["Re-scan affected shards"]

    %% Split-brain
    SB["Split-brain attempt"]
    SB_PREVENT["PREVENTED by<br/>fencing tokens"]
    SB_REJECT["Stale worker rejected<br/>(StaleFence)"]

    START --> WHAT

    WHAT --> WC
    WHAT --> CC
    WHAT --> NP_WC
    WHAT --> NP_WS
    WHAT --> SO
    WHAT --> DC
    WHAT --> SB

    WC --> WC_LEASE
    WC_LEASE --> WC_NEW
    WC_NEW --> WC_RESUME
    WC_RESUME --> WC_OK

    CC --> CC_PERSIST
    CC_PERSIST -->|"Yes"| CC_YES
    CC_YES --> CC_REBUILD
    CC_REBUILD --> CC_RELEASE
    CC_RELEASE --> CC_OK
    CC_PERSIST -->|"No"| CC_NO
    CC_NO --> CC_LOST

    NP_WC --> NP_WC_LEASE
    NP_WC_LEASE --> NP_WC_HEAL
    NP_WC_HEAL --> NP_WC_REACQ
    NP_WC_REACQ --> NP_WC_OK

    NP_WS --> NP_WS_CB
    NP_WS_CB --> NP_WS_PARK
    NP_WS_PARK --> NP_WS_COOL
    NP_WS_COOL --> NP_WS_PROBE
    NP_WS_PROBE --> NP_WS_OK

    SO --> NP_WS_CB

    DC --> DC_REDERIVE
    DC_REDERIVE --> DC_RESCAN

    SB --> SB_PREVENT
    SB_PREVENT --> SB_REJECT

    %% Green: automatic recovery, no data loss
    style WC_OK fill:#DCFCE7,stroke:#166534,color:#166534
    style CC_OK fill:#DCFCE7,stroke:#166534,color:#166534
    style NP_WC_OK fill:#DCFCE7,stroke:#166534,color:#166534
    style NP_WS_OK fill:#DCFCE7,stroke:#166534,color:#166534
    style SB_REJECT fill:#DCFCE7,stroke:#166534,color:#166534

    %% Yellow: requires restart but recoverable
    style CC_NO fill:#FFF7ED,stroke:#9A3412,color:#9A3412
    style DC_REDERIVE fill:#FFF7ED,stroke:#9A3412,color:#9A3412
    style DC_RESCAN fill:#FFF7ED,stroke:#9A3412,color:#9A3412

    %% Red: data loss or severe
    style CC_LOST fill:#FEE2E2,stroke:#991B1B,color:#991B1B

    %% Neutral nodes
    style START fill:#F3F4F6,stroke:#374151,color:#374151
    style WHAT fill:#F3F4F6,stroke:#374151,color:#374151
    style WC fill:#F3F4F6,stroke:#374151,color:#374151
    style CC fill:#F3F4F6,stroke:#374151,color:#374151
    style NP_WC fill:#F3F4F6,stroke:#374151,color:#374151
    style NP_WS fill:#F3F4F6,stroke:#374151,color:#374151
    style SO fill:#F3F4F6,stroke:#374151,color:#374151
    style DC fill:#F3F4F6,stroke:#374151,color:#374151
    style SB fill:#F3F4F6,stroke:#374151,color:#374151

    %% Process nodes (B2 coordination green)
    style WC_LEASE fill:#DCFCE7,stroke:#166534,color:#166534
    style WC_NEW fill:#DCFCE7,stroke:#166534,color:#166534
    style WC_RESUME fill:#DCFCE7,stroke:#166534,color:#166534
    style CC_PERSIST fill:#DCFCE7,stroke:#166534,color:#166534
    style CC_YES fill:#DCFCE7,stroke:#166534,color:#166534
    style CC_REBUILD fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style CC_RELEASE fill:#DCFCE7,stroke:#166534,color:#166534
    style NP_WC_LEASE fill:#DCFCE7,stroke:#166534,color:#166534
    style NP_WC_HEAL fill:#F3F4F6,stroke:#374151,color:#374151
    style NP_WC_REACQ fill:#DCFCE7,stroke:#166534,color:#166534

    %% Connector (B4 red) for circuit breaker path
    style NP_WS_CB fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style NP_WS_PARK fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style NP_WS_COOL fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style NP_WS_PROBE fill:#FEE2E2,stroke:#991B1B,color:#991B1B

    %% Fencing prevention
    style SB_PREVENT fill:#DCFCE7,stroke:#166534,color:#166534
```

**Reading the decision tree.** Green terminal nodes indicate automatic recovery
with no data loss -- the system heals itself. Orange nodes indicate recoverable
situations that require a restart or manual re-scan. The single red terminal
node ("All state lost") represents the only path where work is genuinely lost,
and it only applies to the in-memory backend, which is not used in production.

The tree reveals a reassuring pattern: **most failure paths terminate in
automatic recovery**. Worker crashes, network partitions, and source outages all
resolve through the same two mechanisms -- lease expiry and cursor-based replay.
Split-brain is not a recovery scenario at all; it is prevented outright by the
fencing protocol.

---

## Recovery Principles in Practice

The following table summarizes each failure mode, its detection mechanism, the
recovery path, and the worst-case impact:

| Failure Mode                           | Detection                              | Recovery                                                      | Worst-Case Impact            |
| :------------------------------------- | :------------------------------------- | :------------------------------------------------------------ | :--------------------------- |
| Worker crash mid-page                  | Lease TTL expiry                       | New worker resumes from last committed cursor                 | One page re-processed        |
| Coordinator crash (persistent)         | Worker timeouts on lease ops           | Restart coordinator, rebuild from DB, release expired leases  | Brief unavailability         |
| Coordinator crash (in-memory)          | Worker timeouts on lease ops           | Restart entire run from scratch                               | All in-flight progress lost  |
| Network partition (worker-coordinator) | Lease TTL expiry + commit timeout      | Re-acquire shard with new fencing token after partition heals | One page re-processed        |
| Network partition (worker-source)      | Consecutive timeouts → circuit breaker | Park shard, cooldown, probe, resume                           | Shard temporarily parked     |
| Source outage                          | Same as network partition with source  | Same circuit breaker pattern                                  | Affected connector paused    |
| Split-brain                            | Fencing token comparison (INV-S12)     | Stale writer rejected immediately                             | No impact (prevented)        |
| Data corruption                        | Application-level integrity checks     | Re-derive from source of truth, re-scan affected shards       | Manual intervention required |

Two observations stand out. First, lease TTL expiry is the universal detection
mechanism for any failure involving a worker or the coordinator. The system does
not try to distinguish between a crash, a partition, and a slow worker -- it
treats them all as "the lease holder did not renew in time." This simplification
is deliberate: the correct recovery action (re-acquire with a new token, resume
from last cursor) is the same regardless of the root cause.

Second, cursor-based replay is the universal recovery mechanism for any failure
involving data processing. Whether the failure was a crash, a partition, or a
transient error, the worker resumes from the last committed cursor and
re-processes at most one page. The done-ledger provides a secondary safety net:
even if items appear in overlapping pages, previously committed items are
skipped.

---

## Cross-References

- [Fencing Protocol](./06-fencing-protocol.md) -- the 5-check validation
  preamble and zombie worker resolution that underpin Diagrams 1, 3, and 5
- [Shard and Run State Machines](./05-shard-and-run-state-machines.md) -- the
  state transitions (Active, Done, Split, Parked) referenced throughout
- [End-to-End Scan Flow](./04-end-to-end-scan-flow.md) -- ScanDriver
  architecture and distributed worker loop
- [System Overview](./01-system-overview.md) -- the five architectural
  boundaries (B1-B5) referenced by color coding
- [Circuit Breaker](./09-circuit-breaker.md) -- the circuit breaker state machine
  and cascade prevention that underpin Diagrams 4 and 6

## Source Code References

| Component                                                              | Path                                                                     |
| :--------------------------------------------------------------------- | :----------------------------------------------------------------------- |
| Coordination data types (shard_spec, cursor, pooled, manifest, limits) | `crates/gossip-contracts/src/coordination/`                              |
| Coordination protocol (lease, fencing, shard ops)                      | `crates/gossip-coordination/src/`                                        |
| Connector module (circuit breaker, source abstraction)                 | `crates/gossip-contracts/src/connector/` and `crates/gossip-connectors/` |
| Shard record and state transitions                                     | `crates/gossip-coordination/src/record.rs`                               |
| Fencing validation logic                                               | `crates/gossip-coordination/src/validation.rs`                           |
| Lease management                                                       | `crates/gossip-coordination/src/lease.rs`                                |
| Error types (StaleFence, AcquireError, etc.)                           | `crates/gossip-coordination/src/error.rs`                                |
