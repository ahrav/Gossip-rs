# Distributed Secret Scanner â€” LLM Instructions

## Prime Directive

You are assisting in the design and implementation of a **distributed secret scanner**. Every architectural decision, algorithm choice, and consistency guarantee **must** be traceable to established academic literature, industry-proven implementations, or formal verification results. **Do not invent novel distributed protocols.** If no established solution exists for a problem, say so explicitly and recommend the closest proven alternative with its known tradeoffs.

---

## 1. Foundational Principles

### 1.1 Evidence Hierarchy

When proposing any distributed systems technique, cite backing from this hierarchy (prefer higher):

1. **Formally verified** â€” TLA+ specs, Coq/Isabelle proofs (e.g., IronFleet, Verdi)
2. **Peer-reviewed papers** â€” Published in SOSP, OSDI, NSDI, EuroSys, VLDB, SIGMOD, or similar
3. **Battle-tested implementations** â€” Systems running at scale with public post-mortems (e.g., FoundationDB, CockroachDB, Kafka, etcd, TigerBeetle, ZooKeeper)
4. **Industry white papers / RFCs** â€” AWS, Google, Meta engineering blogs with substantive technical depth
5. **Textbooks** â€” Kleppmann's *Designing Data-Intensive Applications*, Tanenbaum & Van Steen's *Distributed Systems*, Attiya & Welch's *Distributed Computing*

If you cannot cite from levels 1â€“5, explicitly flag the recommendation as **unproven** and explain why you still believe it's sound.

### 1.2 Correctness Over Performance

- Always prefer a **correct-but-slower** approach over a **fast-but-potentially-incorrect** one.
- Performance optimizations are only permitted when accompanied by an argument (ideally mechanized or at least semi-formal) that they preserve correctness invariants.
- Reference: Lamport, "Who Builds a House Without Drawing Blueprints?" (2015); TigerBeetle's Tiger Style methodology.

### 1.3 Invariant-First Design

Every component must declare its invariants upfront as **assert-level contracts**:

- **Safety invariants**: "What must never happen" â€” e.g., a secret must never be reported as scanned if it was not fully scanned.
- **Liveness invariants**: "What must eventually happen" â€” e.g., every submitted scan job must eventually complete or be marked as failed.
- Reference: Alpern & Schneider, "Defining Liveness" (1985); Lamport, "Proving the Correctness of Multiprocess Programs" (1977).

---

## 2. Work Distribution & Coordination

### 2.1 Work Partitioning

- Use **consistent hashing** for assigning scan targets (repos, files, chunks) to workers.
  - Reference: Karger et al., "Consistent Hashing and Random Trees" (STOC 1997).
  - Prefer **jump consistent hash** (Lamping & Veach, 2014) or **rendezvous hashing** (Thaler & Ravishankar, 1998) for simplicity and uniform distribution.
  - Virtual nodes for load balancing per Amazon Dynamo: DeCandia et al., "Dynamo: Amazon's Highly Available Key-Value Store" (SOSP 2007).

### 2.2 Task Scheduling

- Use **work-stealing** for dynamic load balancing across heterogeneous scan workloads.
  - Reference: Blumofe & Leiserson, "Scheduling Multithreaded Computations by Work Stealing" (JACM 1999).
- For coarse-grained job distribution, use a **centralized scheduler with lease-based ownership** rather than peer-to-peer protocols. Leases are simpler to reason about and have well-understood failure semantics.
  - Reference: Gray & Cheriton, "Leases: An Efficient Fault-Tolerant Mechanism for Distributed File Cache Consistency" (SOSP 1989).

### 2.3 Leader Election (If Needed)

- Do not implement custom leader election. Use an existing consensus system (etcd/Raft, ZooKeeper/ZAB).
  - Reference: Ongaro & Ousterhout, "In Search of an Understandable Consensus Algorithm" (USENIX ATC 2014) â€” Raft.
  - Reference: Hunt et al., "ZooKeeper: Wait-free Coordination for Internet-Scale Systems" (USENIX ATC 2010).

---

## 3. Consistency & Correctness Guarantees

### 3.1 Exactly-Once Scan Processing

The scanner must guarantee that every scan unit (chunk, file, repository) is processed **exactly once** under all failure modes. Decompose this into two sub-properties:

- **At-least-once delivery** + **idempotent processing** = **effectively exactly-once**.
  - Reference: Kafka's idempotent producer & transactional semantics â€” Kreps, "Exactly-once Semantics Are Possible" (Confluent 2017); KIP-98, KIP-129.
  - Reference: Akidau et al., "The Dataflow Model: A Practical Approach to Balancing Correctness, Latency, and Cost in Massive-Scale, Unbounded, Out-of-Order Data Processing" (VLDB 2015).

**Implementation pattern**: Assign each scan unit a **deterministic, content-derived ID** (e.g., SHA-256 of `(source, path, revision, chunk_offset)`). Workers write results keyed by this ID. Duplicate writes are idempotent.

### 3.2 Ordering Guarantees

- Define explicitly which operations require ordering and which do not.
- Secret scanning results generally do **not** require total ordering â€” use **causal ordering** where dependencies exist (e.g., a chunk depends on its scan job).
  - Reference: Lamport, "Time, Clocks, and the Ordering of Events in a Distributed System" (CACM 1978).
  - If causal tracking is needed: vector clocks â€” Fidge (1988), Mattern (1989). Prefer **version vectors** for state-based tracking over full vector clocks for message-based tracking.

### 3.3 Consistency Model Selection

- For scan metadata (job status, progress): **linearizable** reads/writes via a consensus-backed store (etcd, CockroachDB, FoundationDB).
  - Reference: Herlihy & Wing, "Linearizability: A Correctness Condition for Concurrent Objects" (TOPLAS 1990).
- For scan results (detected secrets): **eventual consistency** is acceptable provided deduplication is idempotent.
  - Reference: Vogels, "Eventually Consistent" (CACM 2009).
- Be explicit about the CAP trade-off position for each subsystem.
  - Reference: Gilbert & Lynch, "Brewer's Conjecture and the Feasibility of Consistent, Available, Partition-Tolerant Web Services" (SIGACT News 2002).
  - Reference: Kleppmann, "A Critique of the CAP Theorem" (2015) â€” for nuance beyond the binary framing.

### 3.4 Distributed Transactions (If Needed)

- Avoid distributed transactions where possible. Prefer **saga patterns** with compensating actions.
  - Reference: Garcia-Molina & Salem, "Sagas" (SIGMOD 1987).
- If strong atomicity is unavoidable, use **two-phase commit (2PC)** with clear documentation of its blocking failure mode.
  - Reference: Gray, "Notes on Data Base Operating Systems" (1978).
  - Consider **Paxos Commit** for non-blocking atomic commit if availability under partition is required.
  - Reference: Gray & Lamport, "Consensus on Transaction Commit" (TODS 2006).

---

## 4. Fault Tolerance & Recovery

### 4.1 Failure Model

Assume a **crash-recovery** failure model (not Byzantine), unless explicitly stated otherwise.

- Reference: Cachin, Guerraoui, & Rodrigues, *Introduction to Reliable and Secure Distributed Programming* (2011), Chapter 2.
- All components must be designed for **crash-and-restart safety**: any state that survives a restart must be written to durable storage with fsync semantics before being acknowledged.

### 4.2 Checkpointing

- Use **Chandy-Lamport distributed snapshots** for consistent global state capture in streaming scan pipelines.
  - Reference: Chandy & Lamport, "Distributed Snapshots: Determining Global States of Distributed Systems" (TOCS 1985).
  - Practical implementation: Apache Flink's Asynchronous Barrier Snapshotting (ABS).
  - Reference: Carbone et al., "Lightweight Asynchronous Snapshots for Distributed Dataflows" (2015).

### 4.3 Failure Detection

- Use **accrual failure detectors** over binary heartbeat timeouts. They adapt to network conditions and reduce false positives.
  - Reference: Hayashibara et al., "The Phi Accrual Failure Detector" (SRDS 2004).
- Alternatively, use **lease-based liveness** where a worker must renew its lease before expiry, or its work is reassigned.

### 4.4 Retry & Backpressure

- **Exponential backoff with jitter** for retries to avoid thundering herd.
  - Reference: AWS Architecture Blog, "Exponential Backoff and Jitter" (2015); original analysis in Ethernet CSMA/CD (Metcalfe & Boggs, 1976).
- **Backpressure propagation** to prevent producers from overwhelming consumers.
  - Reference: Reactive Streams Specification (reactive-streams.org); TCP flow control (Jacobson, "Congestion Avoidance and Control", 1988).

### 4.5 Circuit Breaking

- Wrap external dependencies (source code hosts, credential stores) with circuit breakers.
  - Reference: Nygard, *Release It!* (2007, 2nd ed. 2018), Chapter 5.
  - States: Closed â†’ Open â†’ Half-Open, with configurable thresholds and recovery probes.

---

## 5. Distributed Scanning Semantics

### 5.1 Chunk Boundary Handling

When scanning files in distributed chunks, secrets may span chunk boundaries. Handle this via **overlap windows**:

- Each chunk includes a configurable overlap region (e.g., 2Ã— max expected secret length) from the adjacent chunk.
- Deduplication by deterministic ID prevents double-reporting of secrets found in overlap regions.
- This is analogous to the **boundary handling in MapReduce text processing**.
  - Reference: Dean & Ghemawat, "MapReduce: Simplified Data Processing on Large Clusters" (OSDI 2004) â€” record boundary handling.

### 5.2 Deduplication

- Use **content-addressable identifiers** for scan results: `hash(source, path, revision, match_offset, detector_id)`.
- For probabilistic pre-filtering (bloom filter checks before expensive dedup lookups):
  - Reference: Bloom, "Space/Time Trade-offs in Hash Coding with Allowable Errors" (CACM 1970).
  - Use **counting Bloom filters** if deletions are needed, or **cuckoo filters** for better space efficiency with deletion support.
  - Reference: Fan et al., "Cuckoo Filter: Practically Better Than Bloom" (CoNEXT 2014).

### 5.3 Scan Completeness Verification

The system must verify that all units of work were scanned (no drops). Implementation pattern:

- Maintain an **expected work manifest** (list of all scan units derived from the enumeration phase).
- Compare against **completed work set** using set reconciliation.
  - Reference: Eppstein et al., "What's the Difference? Efficient Set Reconciliation Without Prior Context" (SIGCOMM 2011).
- Alternatively, use **anti-entropy protocols** for eventual consistency verification.
  - Reference: Demers et al., "Epidemic Algorithms for Replicated Database Maintenance" (PODC 1987).

---

## 6. State Management

### 6.1 State Machine Replication

If the scanner coordinator is replicated for high availability, use **state machine replication** (SMR).

- Reference: Schneider, "Implementing Fault-Tolerant Services Using the State Machine Approach" (CSUR 1990).
- All inputs must be deterministic. Non-determinism (timestamps, random values) must be captured in the replicated log, not generated independently by replicas.

### 6.2 Persistent State

- Use **write-ahead logging (WAL)** for all durable state changes.
  - Reference: Mohan et al., "ARIES: A Transaction Recovery Method Supporting Fine-Granularity Locking" (TODS 1992).
- fsync before acknowledgment. Do not rely on OS buffering for durability.
  - Reference: Pillai et al., "All File Systems Are Not Created Equal: On the Complexity of Crafting Crash-Consistent Applications" (OSDI 2014).

### 6.3 Schema Evolution

- Plan for schema evolution in persisted state from day one. Use **forward-compatible serialization**.
  - Reference: Kleppmann, *Designing Data-Intensive Applications* (2017), Chapter 4 â€” Encoding and Evolution.
  - Prefer Protocol Buffers or FlatBuffers with explicit field numbering and clear deprecation policies.

---

## 7. Observability & Debugging

### 7.1 Distributed Tracing

- Propagate trace context through all scan operations using **W3C Trace Context** or equivalent.
  - Reference: Sigelman et al., "Dapper, a Large-Scale Distributed Systems Tracing Infrastructure" (Google Tech Report, 2010).

### 7.2 Causal Logging

- Logs across workers must be **causally orderable**. Include logical timestamps (hybrid logical clocks).
  - Reference: Kulkarni et al., "Logical Physical Clocks and Consistent Snapshots in Globally Distributed Databases" (OPODIS 2014) â€” Hybrid Logical Clocks (HLC).

---

## 8. Testing & Verification

### 8.1 Deterministic Simulation Testing

- Test distributed components using **deterministic simulation** â€” control all sources of non-determinism (time, I/O, network, random) through a seeded PRNG and simulated environment.
  - Reference: FoundationDB's simulation testing â€” "Testing Distributed Systems w/ Deterministic Simulation" (Apple, 2021 FoundationDB paper & talks).
  - Reference: TigerBeetle's VOPR (Viewstamped Operation Replicator) deterministic simulator.
  - This is the **highest-confidence testing methodology** for distributed correctness. Prioritize it.

### 8.2 Fault Injection

- Systematically inject: process crashes, network partitions, message reordering, message duplication, disk failures, slow I/O.
  - Reference: Alvaro et al., "Lineage-driven Fault Injection" (SIGMOD 2015) â€” LDFI / Molly.
  - Reference: Jepsen (Kingsbury) â€” methodology and tool suite for distributed systems correctness testing.

### 8.3 Model Checking / Formal Methods

- For critical protocol logic (coordinator state machine, checkpoint protocol), write a **TLA+ specification** and model-check it.
  - Reference: Lamport, *Specifying Systems* (2002); "Who Builds a House Without Drawing Blueprints?" (2015).
  - Amazon's use of TLA+: Newcombe et al., "How Amazon Web Services Uses Formal Methods" (CACM 2015).
- The TLA+ spec serves as the **source of truth** for the protocol. Implementation must demonstrably correspond to the spec.

### 8.4 Property-Based Testing

- Use property-based testing for serialization, state transitions, and invariant checking.
  - Reference: Claessen & Hughes, "QuickCheck: A Lightweight Tool for Random Testing of Haskell Programs" (ICFP 2000).
  - In Rust: `proptest` or `quickcheck` crates.

---

## 9. Anti-Patterns â€” Explicit Prohibitions

1. **Do not design novel consensus protocols.** Use Raft (via etcd) or an existing implementation.
2. **Do not assume clocks are synchronized.** Use logical clocks or HLCs for ordering. Physical clocks are for human-readable timestamps only.
3. **Do not conflate "no response" with "failure."** A timeout means unknown â€” handle the ambiguity explicitly. Reference: Fischer, Lynch, Paterson, "Impossibility of Distributed Consensus with One Faulty Process" (JACM 1985) â€” the FLP result.
4. **Do not use unbounded queues.** All queues must have bounded capacity with explicit backpressure behavior.
5. **Do not rely on wall-clock timeouts for correctness** â€” only for leader-election liveness. Correctness logic must be clock-independent.
6. **Do not silently drop scan work.** Every scan unit must reach a terminal state (completed, failed-with-reason) with an auditable trail.
7. **Do not assume network reliability.** Design for: message loss, duplication, reordering, and partitions. Reference: Bailis & Kingsbury, "The Network is Reliable" (ACM Queue 2014).

---

## 10. Response Format Requirements

When proposing any design decision or implementation approach:

1. **State the problem** concisely.
2. **Name the approach** and cite its provenance (paper, system, textbook).
3. **Justify the fit** â€” why this approach matches our constraints.
4. **Enumerate known tradeoffs** â€” what we give up.
5. **Identify invariants** the approach must maintain.
6. **Suggest verification strategy** â€” how we test that invariants hold.

---

## Quick Reference: Key Citations

| Concept | Primary Reference |
|---|---|
| Consensus (Raft) | Ongaro & Ousterhout, USENIX ATC 2014 |
| Consistent Hashing | Karger et al., STOC 1997 |
| Linearizability | Herlihy & Wing, TOPLAS 1990 |
| Exactly-Once Semantics | Akidau et al., VLDB 2015 (Dataflow Model) |
| Distributed Snapshots | Chandy & Lamport, TOCS 1985 |
| Work Stealing | Blumofe & Leiserson, JACM 1999 |
| Leases | Gray & Cheriton, SOSP 1989 |
| FLP Impossibility | Fischer, Lynch, Paterson, JACM 1985 |
| Sagas | Garcia-Molina & Salem, SIGMOD 1987 |
| Failure Detection | Hayashibara et al., SRDS 2004 |
| WAL / ARIES | Mohan et al., TODS 1992 |
| Deterministic Simulation | FoundationDB (Apple, 2021) |
| TLA+ in Industry | Newcombe et al., CACM 2015 |
| Fault Injection (LDFI) | Alvaro et al., SIGMOD 2015 |
| Causal Ordering | Lamport, CACM 1978 |
| Bloom Filters | Bloom, CACM 1970 |
| Cuckoo Filters | Fan et al., CoNEXT 2014 |
| HLC | Kulkarni et al., OPODIS 2014 |
| Crash Consistency | Pillai et al., OSDI 2014 |
| Network Unreliability | Bailis & Kingsbury, ACM Queue 2014 |
| Tiger Style | TigerBeetle Design Document |
