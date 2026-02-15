# Gossip RS â€” Distributed Scanner Contracts: Reference Reading List

> Curated references for the concepts and patterns underlying the `gossip-contracts` crate.
> Organized by contract boundary, with suggested reading order at the bottom.

---

## â‘  Leases & Fencing Tokens (Boundary â‘¡: Coordination)

### Papers & Books

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [Leases: An Efficient Fault-Tolerant Mechanism for Distributed File Cache Consistency](https://web.stanford.edu/class/cs240/readings/89-leases.pdf) | Gray & Cheriton | 1989 | **The original leases paper.** Introduced time-bounded ownership as an alternative to locks. Our entire lease model traces back to this. |
| [Designing Data-Intensive Applications (DDIA)](https://dataintensive.net/) | Martin Kleppmann | 2017 | **Ch 8**: The Trouble with Distributed Systems. **Ch 9**: Consistency and Consensus. Covers leases, fencing, and the impossibility results that motivate "better pause than overlap." Single best book investment for everything in our contracts. |

### Blog Posts & Articles

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [How to do distributed locking](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html) | Martin Kleppmann | 2016 | **The definitive fencing tokens explainer.** Demonstrates why leases alone aren't sufficient â€” GC pauses, network delays, and clock assumptions break naive locks. Shows why monotonically increasing fence epochs are the fix. |
| [Distributed Locks Are Dead; Long Live Distributed Locks!](https://hazelcast.com/blog/long-live-distributed-locks/) | Hazelcast | 2019 | Production fenced lock implementation with monotonic tokens, Jepsen-tested for correctness. Shows the full protocol where all external services participate in the fencing-token protocol. |
| [Locks, Leases, Fencing Tokens, FizzBee!](https://surfingcomplexity.blog/2025/03/03/locks-leases-fencing-tokens-fizzbee/) | Lorin Hochstein | 2025 | Formal modeling of fencing tokens using FizzBee. Reveals edge cases in the fencing token protocol that aren't obvious from informal reasoning. |
| [Modelling distributed locking in TLA+](https://medium.com/@polyglot_factotum/modelling-distributed-locking-in-tla-8a75dc441c5a) | polyglot_factotum | 2022 | TLA+ specification of distributed locking with and without fencing tokens. Good reference for how to formally verify our coordination invariants. |

---

## â‘¡ Idempotency Keys & At-Least-Once Semantics (Boundary â‘¤: Persistence + OpId pattern)

### Blog Posts & Articles

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [Designing robust and predictable APIs with idempotency](https://stripe.com/blog/idempotency) | Brandur Leach (Stripe) | 2017 | **The canonical idempotency key explainer.** Client generates unique ID, server deduplicates. Our `OpId` pattern is exactly this applied to coordination operations. |
| [Implementing Stripe-like Idempotency Keys in Postgres](https://brandur.org/idempotency-keys) | Brandur Leach | 2017 | **Deep implementation guide.** Shows atomic phases, recovery from partial failures, and a completer process. Directly relevant to our `op_id + payload_hash` conflict detection. |
| [Stripe API: Idempotent Requests](https://docs.stripe.com/api/idempotent_requests) | Stripe | â€” | Official Stripe API docs for idempotency keys. Reference implementation for our retry-safety semantics. |
| [Working with the new Idempotency Keys RFC](https://httptoolkit.com/blog/idempotency-keys/) | HTTP Toolkit | 2023 | Covers the IETF draft RFC standardizing the `Idempotency-Key` header pattern across the industry. |

### Standards

| Title | Source | Why It Matters |
|-------|--------|----------------|
| [IETF Draft: Idempotency-Key HTTP Header Field](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) | IETF | The emerging standard for idempotency keys in HTTP APIs. |

---

## â‘¢ Range Sharding & Ordered Keyspaces (Boundary â‘¢: Shard Algebra)

### Papers

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [Spanner: Google's Globally-Distributed Database](https://research.google.com/archive/spanner-osdi2012.pdf) | Corbett et al. (Google) | 2012 | **The definitive range-sharded system.** Tables sharded into tablets along primary key, each tablet = contiguous row range with start/end. Our ShardSpec model is architecturally identical. |
| [Spanner: Becoming a SQL System](https://research.google.com/pubs/archive/46103.pdf) | Bacon et al. (Google) | 2017 | Covers dynamic resharding with query restarts â€” requests cope with ongoing splitting, merging, and moving of data. Our two-layer cursor (token + last_key) solves the same problem. |
| [Bigtable: A Distributed Storage System for Structured Data](https://research.google.com/archive/bigtable-osdi06.pdf) | Chang et al. (Google) | 2006 | Pioneered tablet-based range partitioning with lexicographic byte ordering. Foundational to understanding why lex-ordered bytes are the universal keyspace abstraction. |

### Whitepapers & Documentation

| Title | Source | Why It Matters |
|-------|--------|----------------|
| [Optimizing Schema Design for Cloud Spanner](https://cloud.google.com/spanner/docs/whitepapers/optimizing-schema-design) | Google Cloud | Practical encoding advice: why lex key ordering matters, the timestamp anti-pattern (naive integer encoding), application-level sharding with shard ID prefixes. Directly relevant to our key schema design (PathKey, TimeIdKey, etc). |
| [Life of Spanner Reads & Writes](https://cloud.google.com/spanner/docs/whitepapers/life-of-reads-and-writes) | Google Cloud | Detailed walkthrough of how range sharding, splits, and Paxos leaders interact in production. Shows how splits are dynamic and how the system handles key range ownership changes. |
| [Sharding of timestamp-ordered data in Cloud Spanner](https://cloud.google.com/blog/products/gcp/sharding-of-timestamp-ordered-data-in-cloud-spanner) | Google Cloud Blog | Addresses the exact hot-spot problem our TimeIdKey encoding solves: how to shard timestamp-ordered data without creating write hotspots. |
| [CockroachDB: Range Splits and Merges](https://www.cockroachlabs.com/docs/stable/architecture/distribution-layer.html) | Cockroach Labs | Open-source perspective on range-based sharding with half-open intervals, automatic splitting, and merge semantics. Accessible source code for comparison. |

---

## â‘£ FoundationDB â€” Layered Architecture & Ordered Key-Value Contracts

### Papers

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [FoundationDB: A Distributed Unbundled Transactional Key Value Store](https://www.foundationdb.org/files/fdb-paper.pdf) | Zhou et al. | 2021 | **SIGMOD Best Industry Paper.** The layered architecture (minimal KV contract â†’ layers on top) is the same philosophy as our `gossip-contracts` crate. Also covers deterministic simulation testing in depth. |
| [FoundationDB Record Layer: A Multi-Tenant Structured Datastore](https://www.foundationdb.org/files/record-layer-paper.pdf) | Chrysafis et al. (Apple) | 2019 | How Apple built CloudKit's multi-tenant storage on FoundationDB's ordered KV primitives using contiguous subspaces. Our tenant isolation + ordered keyspace design is architecturally similar. |

### Blog Posts & Analysis

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [How FoundationDB works and why it works](https://uvdn7.github.io/notes-on-the-foundationdb-paper/) | Lu's Blog | 2021 | Excellent detailed walkthrough of the FDB paper with proofs and analysis. Covers the unbundled architecture, deterministic transaction ordering, and recovery. |

---

## â‘¤ Deterministic Simulation Testing (Testing Strategy)

### Foundational Resources

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [FoundationDB SIGMOD Paper â€” Simulation Section](https://www.foundationdb.org/files/fdb-paper.pdf) | Zhou et al. | 2021 | FDB built the simulator *before* the database. Simulates network of processes + disk/process/network failures, all in a single physical process. The gold standard. |
| [What's the big deal about Deterministic Simulation Testing?](https://notes.eatonphil.com/2024-08-20-deterministic-simulation-testing.html) | Phil Eaton | 2024 | Practical walkthrough of building DST: mocking I/O, controlling randomness, running multi-node simulations on a single thread. Good starting point. |

### Production System DST Implementations

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [A Descent Into the VÃ¶rtex](https://tigerbeetle.com/blog/2025-02-13-a-descent-into-the-vortex/) | TigerBeetle | 2025 | Defense-in-depth testing combining DST with generative full-system tests. Injects network faults (delay, loss, corruption) and process faults. Essential reading given our Tiger Style principles. |
| [We Put a Distributed Database In the Browser](https://tigerbeetle.com/blog/2023-07-11-we-put-a-distributed-database-in-the-browser/) | TigerBeetle | 2023 | Covers the VOPR deterministic simulator. 3.3 seconds of simulation = 39 minutes of real-world testing. Shows the power of time dilation in DST. |
| [Deterministic Simulation Testing for Our Entire SaaS](https://www.warpstream.com/blog/deterministic-simulation-testing-for-our-entire-saas) | WarpStream | 2025 | Applied DST to an entire SaaS (not just a DB component). Tests the full data plane + control plane split using Antithesis. Relevant to our worker + coordinator separation. |
| [TigerBeetle Safety](https://docs.tigerbeetle.com/concepts/safety/) | TigerBeetle | â€” | Covers storage fault model, strict serializability, end-to-end idempotency with client-generated u128 IDs, and the VOPR simulator running 24/7 on 1024 cores. |

### Overviews & Primers

| Title | Authors / Source | Year | Why It Matters |
|-------|-----------------|------|----------------|
| [Deterministic Simulation Testing (DST) Primer](https://antithesis.com/resources/deterministic_simulation_testing/) | Antithesis | â€” | Comprehensive overview of what DST is, how to implement it, which systems benefit most. Covers FoundationDB, TigerBeetle, WarpStream, and others. |
| [A DST Primer for Unit Test Maxxers](https://www.amplifypartners.com/blog-posts/a-dst-primer-for-unit-test-maxxers) | Amplify Partners | â€” | Covers the history and theory of DST from FoundationDB through modern implementations. Includes the Hurst Exponent for correlated failure injection. |
| [Issue #9: Deterministic Simulation Testing](https://dtornow225.substack.com/p/issue-9-deterministic-simulation) | Daniel Tornow | 2024 | Formal treatment of determinism in distributed systems. Defines traces, execution spaces, and what it means for a system to be deterministic under a runtime. |
| [awesome-deterministic-simulation-testing](https://github.com/ivanyu/awesome-deterministic-simulation-testing) | GitHub (ivanyu) | â€” | **Curated list** of DST resources, implementations, talks, and frameworks including Rust-specific options like `madsim`. |

---

## â‘¥ Content-Addressed Identity & Deterministic IDs

### Related Concepts

| Title | Source | Why It Matters |
|-------|--------|----------------|
| [Git Internals â€” Git Objects](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects) | Pro Git Book | Git's content-addressed object model (SHA-1 of content = object ID) is the same principle as our deterministic FindingId derivation. Same content â†’ same ID, always. |
| [IPFS Content Addressing](https://docs.ipfs.tech/concepts/content-addressing/) | Protocol Labs | Content-addressed storage at scale. CIDs (Content Identifiers) are derived from content hashes, enabling deduplication and verification â€” same pattern as our SecretHash and FindingId. |
| [Merkle Trees and Content Addressability](https://en.wikipedia.org/wiki/Merkle_tree) | Wikipedia | The data structure underlying content-addressed systems. Relevant to understanding why deterministic hashing enables both dedup and integrity verification. |

---

## â‘¦ Secret Hashing & Keyed MACs (Boundary â‘ : Identity spine)

### Standards & References

| Title | Source | Why It Matters |
|-------|--------|----------------|
| [HMAC: Keyed-Hashing for Message Authentication (RFC 2104)](https://datatracker.ietf.org/doc/html/rfc2104) | IETF | The standard for HMAC construction. Our `SecretHash = HMAC(tenant_key, normalized_bytes)` follows this exactly. |
| [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) | BLAKE3 Team | Our engine's internal `NormHash = blake3(secret_bytes)`. BLAKE3 also supports keyed hashing natively, which could simplify the keyed/unkeyed boundary. |

---

## â‘§ General Distributed Systems Theory

### Books (Priority Order)

| Title | Authors | Why It Matters |
|-------|---------|----------------|
| [Designing Data-Intensive Applications](https://dataintensive.net/) | Martin Kleppmann | **#1 priority.** Chapters 5-9 cover replication, partitioning, transactions, distributed system failures, and consensus. Nearly every concept in our contracts maps to a chapter here. |
| [Introduction to Reliable and Secure Distributed Programming](https://link.springer.com/book/10.1007/978-3-642-15260-3) | Cachin, Guerraoui, Rodrigues | Kleppmann recommends this for the formal theory. Covers consensus algorithms, broadcast abstractions, and failure detectors rigorously. |
| [ZooKeeper: Distributed Process Coordination](https://www.oreilly.com/library/view/zookeeper/9781449361297/) | Junqueira & Reed | Practical coordination service patterns: leader election, distributed locks, group membership. Relevant to our coordinator backend design. |

---

## Suggested Reading Order

For maximum value given where we are in the design:

| Order | Resource | Time | Grounds |
|-------|----------|------|---------|
| 1 | [Kleppmann: How to do distributed locking](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html) | ~30 min | Boundary â‘¡ (fencing) |
| 2 | [Stripe: Designing robust APIs with idempotency](https://stripe.com/blog/idempotency) | ~20 min | OpId pattern |
| 3 | [Spanner: Optimizing Schema Design](https://cloud.google.com/spanner/docs/whitepapers/optimizing-schema-design) | ~45 min | Boundary â‘¢ (keyspace) |
| 4 | [Phil Eaton: DST overview](https://notes.eatonphil.com/2024-08-20-deterministic-simulation-testing.html) | ~30 min | Testing strategy |
| 5 | [FoundationDB SIGMOD paper](https://www.foundationdb.org/files/fdb-paper.pdf) | ~2 hrs | Layered architecture + DST |
| 6 | [DDIA Chapters 8-9](https://dataintensive.net/) | ~4 hrs | Everything tied together |
| 7 | [TigerBeetle: A Descent Into the VÃ¶rtex](https://tigerbeetle.com/blog/2025-02-13-a-descent-into-the-vortex/) | ~30 min | Tiger Style DST |
| 8 | [Brandur: Idempotency Keys in Postgres](https://brandur.org/idempotency-keys) | ~45 min | Persistence sink impl |
| 9 | [Spanner OSDI 2012 paper](https://research.google.com/archive/spanner-osdi2012.pdf) | ~2 hrs | Range sharding at scale |
| 10 | [FDB Record Layer paper](https://www.foundationdb.org/files/record-layer-paper.pdf) | ~1.5 hrs | Multi-tenant on KV |

---

*Last updated: 2026-02-10*
*Context: Reference material for gossip-contracts crate design in Gossip RS*
