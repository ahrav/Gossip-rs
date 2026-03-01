# Circuit Breaker

> **Implementation status: Design Target.** The circuit breaker types described below
> (`CircuitBreakerState`, `CircuitConfig`) do **not** exist in compiled source code. The
> current retry mechanism is a consecutive-failure counter in the scan loop
> (`scan_loop.rs:131`, `DEFAULT_MAX_TRANSIENT_RETRIES = 3`). This document describes the
> target design for a future circuit breaker implementation.

The circuit breaker is a fault-isolation mechanism in the **B4 Connector** boundary that
prevents cascading failures when external data sources become unavailable. The core
insight, first articulated by Michael Nygard in *Release It!* (2007, 2nd ed. 2018), is
deceptively simple: **when a source is down, stop calling it**. Instead of letting
hundreds of workers block on timeouts and retries against a failing API, the circuit
breaker trips open after a small number of consecutive failures and begins rejecting
requests immediately -- no network call, no timeout, no blocked thread.

This matters enormously for system throughput. Without a circuit breaker, a single
degraded source (say, GitHub returning 503s) can drag down the entire scanner: every
worker that encounters a GitHub shard blocks for 30 seconds waiting for a timeout, then
retries, then blocks again. Within minutes, all workers are stuck waiting on a source
that cannot serve them, and throughput for *every other source* drops to zero. The
circuit breaker eliminates this failure mode by converting a slow failure (timeout) into
a fast failure (immediate rejection), freeing workers to move on to productive work.

Each connector maintains its own independent circuit breaker, providing fault isolation
at the source level. GitHub being down does not affect S3 scanning. S3 rate-limiting
does not affect GitLab. This per-connector isolation is a direct consequence of the
boundary architecture: B4 connectors are independent units with no shared mutable state
between them.

> **Notation.** All diagrams use the B4 Connector color palette (red theme: fill
> `#EF4444`, light fill `#FEE2E2`, stroke `#991B1B`). Dashed lines represent failure
> paths. Solid lines represent success paths.

---

## 1. Circuit Breaker State Machine

The circuit breaker has exactly three states. The state machine is small by design --
the value is in the transitions, not the states. Each transition carries a precise
trigger condition and a concrete system effect.

**Closed** is the normal operating state. All requests flow through to the external
source. The breaker tracks failures in a sliding time window (typically 10 seconds).
Every success resets the failure count. When the failure count exceeds a threshold
(typically 3-5 failures within the window), the breaker trips to Open.

**Open** is the fail-fast state. No requests reach the external source. Every incoming
request is rejected immediately with a `CircuitBreakerOpen` error. This gives the
source time to recover without being hammered by retry traffic. The breaker stays Open
for a configurable cooldown period (typically 30-60 seconds).

**HalfOpen** is the probe state. After the cooldown expires, the breaker allows exactly
one request through as a probe. If the probe succeeds, the source has recovered and the
breaker closes. If the probe fails, the source is still down and the breaker reopens
for another cooldown period.

```mermaid
%% Diagram: circuit-breaker-state-machine
stateDiagram-v2
    direction TB

    [*] --> Closed : Initial state

    Closed --> Closed : success<br/>(reset failure count)
    Closed --> Open : N failures in M seconds<br/>(threshold exceeded)

    Open --> HalfOpen : After timeout T<br/>(cooldown expired)

    HalfOpen --> Closed : Probe request succeeds<br/>(source recovered)
    HalfOpen --> Open : Probe request fails<br/>(source still down)

    note right of Closed
        Normal operation
        All requests flow through
        Track failures in sliding window
        Reset count on success
    end note

    note right of Open
        Fail fast — reject immediately
        No requests to source
        Give source time to recover
        Wait for timeout T
    end note

    note right of HalfOpen
        Probe — allow exactly 1 request
        If success → close circuit
        If failure → reopen circuit
    end note

    classDef closedState fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    classDef openState fill:#EF4444,stroke:#991B1B,color:#FFFFFF
    classDef halfOpenState fill:#FEE2E2,stroke:#991B1B,color:#991B1B

    class Closed closedState
    class Open openState
    class HalfOpen halfOpenState
```

The three states correspond to three distinct behaviors from the caller's perspective:

| State | Caller Experience | Source Load | Thread Impact |
|:------|:------------------|:------------|:--------------|
| Closed | Normal latency, normal errors | Full traffic | Workers block on I/O normally |
| Open | Immediate `CircuitBreakerOpen` error | Zero traffic | Workers freed instantly |
| HalfOpen | One probe in-flight, others rejected | Single request | One worker probes, others freed |

Typical configuration thresholds:

- **Failure threshold**: 3-5 failures within the sliding window
- **Sliding window**: 10 seconds
- **Cooldown timeout (T)**: 30-60 seconds
- **Probe count in HalfOpen**: exactly 1

> **Note:** These thresholds are design guidance. `CircuitConfig` defines them as
> runtime-configurable parameters, not protocol constants.

---

## 2. Cascade Prevention

The circuit breaker's value becomes concrete when you compare system behavior with and
without it during a source outage. The contrast is stark.

**Without a circuit breaker**, the failure cascades. Suppose GitHub starts returning
503 errors. Worker 1 sends a request, waits 30 seconds for a timeout, retries. Worker
2 does the same. Worker 3, 4, 5, ... 100 all pile on. Within seconds, every worker in
the pool is blocked waiting on GitHub. No worker is available to process S3 shards,
GitLab shards, or any other source. The system's effective throughput drops to zero
even though GitHub is the only source that is down. This is the cascading failure
pattern: one component's failure propagates to consume all shared resources (worker
threads).

**With a circuit breaker**, the failure is contained. The first few workers hit GitHub,
get errors, and the circuit breaker records the failures. After the threshold is
reached, the breaker trips open. Every subsequent worker that tries to access GitHub
gets an immediate `CircuitBreakerOpen` rejection -- no network call, no 30-second
timeout. Those workers park their GitHub shards and move on to process S3 and GitLab
shards. System throughput for healthy sources is unaffected.

```mermaid
%% Diagram: cascade-prevention
sequenceDiagram
    autonumber
    participant W1 as Worker 1
    participant W2 as Worker 2
    participant W6 as Worker 6
    participant W7 as Worker 7
    participant CB as Circuit Breaker
    participant GH as Source (GitHub)

    Note over W1,GH: GitHub begins returning 503 errors

    W1->>CB: enumerate(github_shard)
    CB->>GH: GET /repos/...
    GH-->>CB: 503 Service Unavailable
    CB-->>W1: Err(SourceError)
    Note over CB: failure_count: 1

    W2->>CB: enumerate(github_shard)
    CB->>GH: GET /repos/...
    GH-->>CB: 503 Service Unavailable
    CB-->>W2: Err(SourceError)
    Note over CB: failure_count: 2

    Note over CB: Workers 3, 4, 5 also fail...
    Note over CB: failure_count: 5 >= threshold (5)

    rect rgb(254, 226, 226)
        Note over CB: CIRCUIT OPEN — fail fast mode
        W6->>CB: enumerate(github_shard)
        CB--xW6: Err(CircuitBreakerOpen)
        Note right of W6: No network call!<br/>Immediate rejection
    end

    Note right of W6: Worker 6 parks shard<br/>(ParkReason::TooManyErrors)<br/>Moves to next available shard<br/>Thread freed for productive work

    Note over CB: Cooldown timer: 30 seconds...

    rect rgb(254, 226, 226)
        Note over CB: HALF-OPEN — probe mode
        W7->>CB: enumerate(github_shard)
        CB->>GH: GET /repos/... (probe)
        GH-->>CB: 200 OK
        CB-->>W7: Ok(page_data)
        Note over CB: Probe succeeded!
    end

    Note over CB: CIRCUIT CLOSED — normal operation resumes
```

The critical moment is step 8: Worker 6's request never reaches GitHub. The circuit
breaker rejects it immediately, returning `CircuitBreakerOpen` without making any
network call. Worker 6 is freed in microseconds instead of blocking for 30 seconds.
It parks the shard, releases the lease, and moves on to productive work -- perhaps
processing an S3 shard or a GitLab shard that is perfectly healthy.

After the cooldown period expires, the breaker transitions to HalfOpen and allows
Worker 7's request through as a probe. When the probe succeeds (step 12), the breaker
closes and normal operation resumes. If the probe had failed, the breaker would have
reopened for another cooldown period, and the cycle would repeat until the source
recovers.

---

## 3. Per-Connector Isolation

Each connector in the system maintains its own independent circuit breaker. This is
the fault-isolation property that prevents a single source outage from affecting the
entire system. The diagram below shows a snapshot where GitHub is experiencing an
outage (circuit open) while S3 and GitLab are operating normally (circuits closed).

Workers processing S3 shards and GitLab shards are completely unaffected by the GitHub
outage. Only workers that attempt to process GitHub shards encounter the open circuit,
and they handle it by parking their shards and moving on to other work.

```mermaid
%% Diagram: per-connector-isolation
graph TD
    subgraph Workers["Worker Pool"]
        W1["Worker 1<br/>processing S3 shard"]
        W2["Worker 2<br/>processing GitLab shard"]
        W3["Worker 3<br/>parks GitHub shard"]
    end

    subgraph Connectors["Connector Layer (B4)"]
        direction TB

        subgraph GH_Group["GitHub Connector"]
            GH_CB{"GitHub CB<br/><b>OPEN</b><br/>503 errors"}
        end

        subgraph S3_Group["S3 Connector"]
            S3_CB{"S3 CB<br/><b>CLOSED</b><br/>healthy"}
        end

        subgraph GL_Group["GitLab Connector"]
            GL_CB{"GitLab CB<br/><b>CLOSED</b><br/>healthy"}
        end
    end

    subgraph Sources["External Sources"]
        GH_API["GitHub API<br/>503 — DOWN"]
        S3_API["S3 API<br/>200 — healthy"]
        GL_API["GitLab API<br/>200 — healthy"]
    end

    W3 -->|"CircuitBreakerOpen<br/>(immediate reject)"| GH_CB
    GH_CB -.->|"blocked"| GH_API

    W1 -->|"request"| S3_CB
    S3_CB -->|"passes through"| S3_API

    W2 -->|"request"| GL_CB
    GL_CB -->|"passes through"| GL_API

    style W1 fill:#FEE2E2,stroke:#991B1B,color:#000
    style W2 fill:#FEE2E2,stroke:#991B1B,color:#000
    style W3 fill:#FEE2E2,stroke:#991B1B,color:#000

    style GH_CB fill:#EF4444,stroke:#991B1B,color:#FFF
    style S3_CB fill:#22C55E,stroke:#166534,color:#FFF
    style GL_CB fill:#22C55E,stroke:#166534,color:#FFF

    style GH_API fill:#FEE2E2,stroke:#991B1B,color:#000
    style S3_API fill:#DCFCE7,stroke:#166534,color:#000
    style GL_API fill:#DCFCE7,stroke:#166534,color:#000

    style GH_Group fill:#FEE2E2,stroke:#991B1B,color:#000
    style S3_Group fill:#DCFCE7,stroke:#166534,color:#000
    style GL_Group fill:#DCFCE7,stroke:#166534,color:#000

    linkStyle 0 stroke:#EF4444,stroke-dasharray:0
    linkStyle 1 stroke:#EF4444,stroke-dasharray:5
    linkStyle 2 stroke:#22C55E
    linkStyle 3 stroke:#22C55E
    linkStyle 4 stroke:#22C55E
    linkStyle 5 stroke:#22C55E
```

The per-connector isolation follows directly from the boundary architecture. Each
connector is an independent implementation of the connector trait, with its own
configuration, its own rate limiter, and its own circuit breaker. There is no shared
state between connectors that could allow a failure in one to propagate to another.

Key observations:

- **Worker 3** receives `CircuitBreakerOpen` immediately when it attempts to process
  a GitHub shard. It parks the shard with `ParkReason::TooManyErrors`, releases
  the lease, and is free to claim a shard from a healthy source.
- **Workers 1 and 2** are completely unaware that GitHub is down. Their requests flow
  through their respective circuit breakers (both closed) to healthy APIs.
- **The dashed line** from the GitHub circuit breaker to the GitHub API indicates that
  no traffic flows on this path while the circuit is open. The API receives zero
  requests, giving it maximum opportunity to recover.

**ParkReason variants** — when a circuit breaker trips, the worker parks the shard with
`ParkReason::TooManyErrors`. For the full `ParkReason` enum and all variants, see
[Shard and Run State Machines — ParkReason table](05-shard-and-run-state-machines.md).

---

## 4. Shard Parking Flow

When a circuit breaker trips, the system does not simply discard the work -- it parks
the shard so that it can be retried later when the source recovers. The decision flow
below traces the complete path from a connector call through circuit breaker evaluation
to either successful processing or shard parking.

The diagram below focuses on the parking integration -- what happens after the
circuit breaker rejects a request. For the full CB state machine (Closed, Open,
HalfOpen transitions), see Diagram 1 above.

```mermaid
%% Diagram: shard-parking-flow
graph TD
    START(["Worker calls<br/>connector.enumerate()"])
    CB_CHECK{"Circuit<br/>breaker<br/>state?"}
    SUCCESS["Request succeeds<br/>Return page data"]
    CB_OPEN["CircuitBreakerOpen<br/>(immediate reject)"]
    PARK["Park shard<br/>(ParkReason::TooManyErrors)"]
    RELEASE["Release lease"]
    NEXT["Claim next<br/>available shard"]

    START --> CB_CHECK
    CB_CHECK -->|"Closed: call succeeds"| SUCCESS
    CB_CHECK -->|"Open: reject immediately"| CB_OPEN
    CB_CHECK -->|"HalfOpen: probe fails"| CB_OPEN
    CB_OPEN --> PARK
    PARK --> RELEASE
    RELEASE --> NEXT

    NOTE["See Diagram 1 for full<br/>CB state machine details"]

    style START fill:#FEE2E2,stroke:#991B1B,color:#000
    style CB_CHECK fill:#FEE2E2,stroke:#991B1B,color:#000
    style SUCCESS fill:#22C55E,stroke:#166534,color:#FFF
    style CB_OPEN fill:#EF4444,stroke:#991B1B,color:#FFF
    style PARK fill:#F3F4F6,stroke:#374151,color:#000
    style RELEASE fill:#F3F4F6,stroke:#374151,color:#000
    style NEXT fill:#F3F4F6,stroke:#374151,color:#000
    style NOTE fill:#F3F4F6,stroke:#374151,color:#6B7280
```

Regardless of *how* the circuit breaker determined the source is unavailable (threshold
exceeded, open-state rejection, or failed probe), the worker's response is the same --
park the shard and move on. All `CircuitBreakerOpen` paths converge on the same
parking flow.

The parking flow is significant because it integrates the circuit breaker with the
coordination protocol (B2). When a worker parks a shard:

1. **`coordinator.park_shard(ParkReason::TooManyErrors)`** transitions the shard
   to the `Parked` terminal state. This is a normal shard state transition through the
   B2 coordination backend, subject to the same fencing token validation as any other
   mutation.
2. **The lease is released**, freeing the shard from this worker's ownership. The
   worker's fencing token for this shard becomes stale.
3. **The worker moves on** to the next available shard, which may belong to a completely
   different source. The worker thread is never blocked -- it is always doing productive
   work or quickly discovering that it cannot.

This is the fundamental throughput guarantee: **INV-L30** (if a source API is healthy,
enumeration of its shards eventually completes) is enforced by the circuit breaker. The circuit breaker is the mechanism that
ensures unhealthy sources do not prevent healthy ones from making progress. Workers are
a shared resource, and the circuit breaker prevents any single source from monopolizing
them.

---

## Cross-References

- [Shard and Run State Machines](05-shard-and-run-state-machines.md) -- the `Parked`
  terminal state that shards enter when the circuit breaker trips
- [Fencing Protocol](06-fencing-protocol.md) -- fencing token validation that guards
  the `park_shard` mutation
- [System Overview](01-system-overview.md) -- the five-boundary architecture and how
  B4 Connector fits within it

## Source Code References

- **Connector design doc**: `docs/boundary-4-connectors.md`
- **Connector module**: `crates/gossip-connectors/`
- **Connector trait**: `crates/gossip-contracts/src/connector/`
- **Scan loop retry logic**: `crates/gossip-scan-pipeline/src/scan_loop.rs`
- **Coordination backend**: `crates/gossip-coordination/src/traits.rs`
- **Park reason types**: `crates/gossip-coordination/src/record.rs`
