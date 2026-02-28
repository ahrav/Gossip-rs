# Boundary 5 -- Persistence Architecture

## 1. Overview

Boundary 5 (Persistence) manages durable storage for three distinct data
subsystems: coordination state, the done-ledger (deduplication index), and
scan findings. The shared trait surface (`DoneLedger`, `FindingsSink`,
`PageCommit<S>`) lives in `crates/gossip-contracts/src/persistence/`, and
the production backends will live in separate crates (TBD).

This document captures the storage architecture decisions derived from
research into workload characteristics, scale requirements, and consistency
semantics. It is the normative reference for anyone implementing the
production persistence backends.

### Storage topology

| Subsystem | Store | Why this store |
|-----------|-------|----------------|
| Coordination (shard records, run records, leases, fences) | **ScyllaDB** (LWT for CAS) | Single-row CAS maps to LWT; co-located partitions enable atomic splits |
| Done-ledger (deduplication index) | **ScyllaDB** (LWW for CRDT merge) | Pure KV at 15 TB; LWW timestamp trick maps `Scanned > Failed` for free |
| Findings + occurrences (detected secrets) | **PostgreSQL** | Triage UI needs SQL: filter, sort, aggregate, join, full-text search |

**Total external systems: 2** (ScyllaDB cluster + PostgreSQL).

### Scale targets

| Parameter | Value | Notes |
|-----------|-------|-------|
| Minimum shard size | 5-10 GB | Smaller shards defeat scanner throughput |
| Scanner throughput | 100-3000 MB/s per worker | Moderate m1 8-core machine |
| Active shards (concurrent) | 200-10,000 | Depends on fleet size |
| Total shards (PB scale) | 100K-1M | `DEFAULT_MAX_TOTAL_SHARDS = 1_000_000` |
| Checkpoint writes/sec | 40-2,000 | At 5-second checkpoint intervals |
| Done-ledger entries | 100M-100B | 15 GB to 15 TB |
| Findings | 1M-100M | 0.3-30 GB |
| Occurrences | 5M-500M | 1-100 GB |

---

## 2. ScyllaDB: Coordination State

### 2.1 Schema

All shard records for a run **must** share a partition to enable atomic
split operations via single-partition LWT batches.

```sql
CREATE TABLE coordination.shards (
    tenant_id       blob,
    run_id          blob,
    shard_id        bigint,
    status          tinyint,        -- ShardStatus discriminant
    fence_epoch     bigint,
    lease_holder    blob,           -- WorkerId, NULL if unleased
    lease_deadline  bigint,         -- LogicalTime
    cursor_last_key blob,
    cursor_token    blob,
    cursor_semantics tinyint,
    spec_start      blob,           -- key_range_start
    spec_end        blob,           -- key_range_end
    spec_metadata   blob,           -- ShardHint
    parent_shard    bigint,         -- NULL for root shards
    spawned_ids     blob,           -- concatenated child ShardIds
    op_log          blob,           -- serialized RingBuffer<OpLogEntry, 16>
    park_reason     tinyint,        -- NULL if not parked
    PRIMARY KEY ((tenant_id, run_id), shard_id)
) WITH CLUSTERING ORDER BY (shard_id ASC);

CREATE TABLE coordination.runs (
    tenant_id       blob,
    run_id          blob,
    status          tinyint,        -- RunStatus discriminant
    cursor_semantics tinyint,
    lease_duration  bigint,
    max_shard_retries int,
    created_at      bigint,
    completed_at    bigint,
    root_shards     blob,           -- serialized Vec<ShardId>
    op_log          blob,           -- serialized RingBuffer<RunOpLogEntry, 8>
    PRIMARY KEY ((tenant_id), run_id)
);
```

**Partition key choice**: `(tenant_id, run_id)` for shards ensures all
shards in a run co-locate on the same ScyllaDB partition. This enables
single-partition LWT batches for split operations. The partition may grow
large (up to `MAX_INITIAL_SHARDS = 10_000` rows plus split children), but
each row is small (~200-500 bytes) so the partition stays under ScyllaDB's
practical limit (~100 MB).

### 2.2 Operation classification

**9 of 13 operations are single-row CAS** and map directly to ScyllaDB LWT:

| Operation | CAS condition | Frequency |
|-----------|---------------|-----------|
| `acquire_and_restore_into` | `IF fence_epoch = :expected AND status = 0` | Per shard claim |
| `renew` | `IF fence_epoch = :expected` | Per lease renewal |
| `checkpoint` | `IF fence_epoch = :expected` | **Hot path** (40-2000/sec) |
| `complete` | `IF fence_epoch = :expected AND status = 0` | Terminal, once |
| `park_shard` | `IF fence_epoch = :expected AND status = 0` | Terminal, once |
| `create_run` | `IF NOT EXISTS` | Once per run |
| `complete_run` | `IF status = 1` (Active) | Once per run |
| `fail_run` / `cancel_run` | `IF status` precondition | Once per run |
| `unpark_shard` | `IF status = 3` (Parked) | Admin, rare |

All use single-partition LWT. Expected LWT throughput: 500-5000 ops/sec per
partition, which exceeds our peak of ~2000 checkpoint writes/sec.

**LWT latency**: 5-15ms per operation (Paxos round-trip). This is acceptable
because workers process 5-10 GB shards over minutes; a 10ms checkpoint
latency is negligible.

**3 operations require multi-row atomicity:**

| Operation | Rows | Solution |
|-----------|------|----------|
| `split_replace` | 1 parent + 2-256 children | Single-partition conditional batch (same `(tenant, run)`) |
| `split_residual` | 1 parent + 1 child | Single-partition conditional batch |
| `register_shards` | 1 run + up to 10,000 shards | Saga pattern (see Section 2.3) |

### 2.3 `register_shards` saga pattern

ScyllaDB LWT batches should stay under ~100-200 rows. `register_shards`
can write up to 10,000 shard records. The solution is a saga with the run
status as the commit point:

```
Step 1: Write shard records in chunks of 100 (unconditional INSERT).
        Shards are keyed by deterministic BLAKE3-derived ShardId,
        so re-inserting an already-written shard is a no-op.

Step 2: If any chunk fails, retry it. Already-written shards are
        idempotent (same key, same value).

Step 3: Once ALL shards are written, CAS the run record:
        UPDATE runs SET status = 1 WHERE ... IF status = 0;
        (Initializing -> Active)

Step 4: The run status flip IS the commit point.
```

**Failure modes:**

| Failure point | State | Recovery |
|---------------|-------|----------|
| Crash during Step 1 | Some shards written, run still Initializing | Retry from beginning. Written shards are idempotent. |
| Crash during Step 3 | All shards written, run still Initializing | Retry Step 3 only. |
| Step 3 CAS fails (concurrent modification) | All shards written | Return error. Caller retries or investigates. |

**Workers cannot see partially-registered runs** because `collect_claim_
candidates_into` only returns shards from `Active` runs. Until Step 3
succeeds, the run is `Initializing` and invisible to workers.

The `create_run_with_shards` default method in `run.rs:1617-1624` already
documents this TOCTOU window and notes that production backends should
override it. This saga is the production override.

**Orphaned shard cleanup:** If a registration is permanently abandoned
(run remains in `Initializing` beyond a configurable timeout), a periodic
garbage collector should delete shard records whose run is still
`Initializing` after N hours. At 10K shards × ~300 bytes per failed
registration, the storage leak is ~3 MB per failure — negligible at
expected failure rates, but unbounded if left unaddressed.

### 2.4 Properties NOT needed from the coordination store

These simplify backend selection:

- **No etcd watches.** Events are inert data returned alongside operation
  results (`events.rs:5,16-17`). The system is pull-based.
- **No external TTL.** Leases are application-level timestamp comparisons
  (`now < deadline`). Expiry is lazily detected, not actively revoked.
  ScyllaDB row TTL is not used.
- **No cross-table transactions.** The coordination store and done-ledger
  are independent. Ordering is enforced by the `PageCommit` typestate at
  the worker level, not by cross-store transactions.

---

## 3. ScyllaDB: Done-Ledger

### 3.1 Workload characteristics

The done-ledger answers: "has this versioned object been scanned under this
policy for this tenant?" It is a pure KV workload with no SQL requirements.

| Property | Value |
|----------|-------|
| Key | `DoneLedgerKey`: 96 bytes fixed (`TenantId[32] \|\| PolicyHash[32] \|\| OvidHash[32]`). BLAKE3-derived, excellent uniformity. |
| Value | `DoneLedgerEntry`: ~50 bytes (`status[1] + scanned_at[8] + run_id[8] + shard_id[8]` + overhead) |
| Write pattern | Batch upsert (100 items/batch), fence-gated, monotonic merge (CRDT) |
| Read pattern | Batch point-lookup (100 keys/batch). Binary: exists + status. |
| Scale | 100M to 100B entries. 15 GB to 15 TB. |
| No range scans | No joins, no aggregations, no deletes in hot path. |

### 3.2 Why ScyllaDB (not Postgres)

- **96-byte keys in a B-tree** (Postgres) = ~40 keys per 4 KB page, 7 levels
  deep at 100B entries. Every lookup = 7 random reads.
- **No merge operator** in Postgres. `ON CONFLICT DO UPDATE` is a
  read-modify-write that creates dead tuples. 50K upserts/sec =
  4.3B dead tuples/day of VACUUM pressure.
- **15 TB in Postgres** requires partitioning. The done-ledger doesn't need
  SQL -- it's a pure KV problem.
- **ScyllaDB's shard-per-core architecture** gives O(1) point lookups at any
  scale. 1.5M reads/sec per node. A 3-node cluster handles our workload at
  <10% utilization.

### 3.3 CRDT merge via LWW timestamps

`DoneLedgerStatus` forms a join-semilattice: `Scanned(2)` absorbs
`Failed(1)`. Instead of using LWT (expensive Paxos) for the merge, encode
the status into the CQL write timestamp:

```
USING TIMESTAMP = (status_discriminant << 56) | logical_time
```

**`logical_time` constraint:** The upper 8 bits are reserved for the status
discriminant, so `logical_time` must fit in 56 bits (< 2^56). In practice
this is a monotonic microsecond counter (epoch-relative). At microsecond
granularity, 2^56 microseconds ≈ 2.28 billion years — overflow is not a
practical concern. Implementations must reject or mask values ≥ 2^56 to
prevent corrupting the status discriminant.

ScyllaDB's built-in Last-Writer-Wins (LWW) resolution uses the highest
timestamp. Since `Scanned(2) << 56` > `Failed(1) << 56`, a `Scanned` write
always wins over a `Failed` write regardless of arrival order. This gives
correct CRDT merge semantics with **zero LWT overhead** -- normal writes only.

```sql
CREATE TABLE done_ledger.entries (
    tenant_id       blob,
    policy_hash     blob,
    ovid_hash       blob,
    status          tinyint,
    scanned_at      bigint,
    run_id          blob,
    shard_id        bigint,
    PRIMARY KEY ((tenant_id, policy_hash), ovid_hash)
);
```

**Partition key**: `(tenant_id, policy_hash)`. All entries for a tenant+policy
co-locate. Policy-change invalidation = dropping the partition (or
range-based TTL).

### 3.4 Fence-epoch enforcement

The done-ledger's `batch_upsert` carries `(shard_id, fence_epoch)`. The
store must reject writes where `epoch <= last_accepted_epoch[shard_id]`.

**Under CRDT merge, fence violations are bounded in impact:** a stale
worker's `Failed` cannot regress a `Scanned` (the LWW timestamp ensures
this). The fence primarily prevents wasted work, not correctness violations.

Implementation: maintain a `fence_watermarks` table. Before `batch_upsert`,
read the watermark and reject if stale. The watermark check is a normal
read + compare at the application level, not an LWT. The CRDT merge
guarantees that even if a stale write sneaks through a race, the result
converges correctly.

```sql
CREATE TABLE done_ledger.fence_watermarks (
    shard_id        bigint,
    fence_epoch     bigint,
    PRIMARY KEY (shard_id)
);
```

### 3.5 The done-ledger MUST be global

`OvidHash` is derived from `(ConnectorTag, ConnectorInstanceId, StableItemId,
ObjectVersionId, SubresourceKind)` -- none of these include `ShardId`. When
a shard splits, items near the boundary may end up in a different child
shard. A shard-local done-ledger would miss the parent's scan results.

The Mercator web crawler paper (Heydon & Najork, 1999) establishes the
principle: "The URL-seen? test is a single shared data structure... We
cannot simply partition it across machines."

The done-ledger is range-partitioned by `(TenantId, PolicyHash)` prefix,
which is correct -- all workers in a run share the same tenant+policy and
query the same partition.

---

## 4. PostgreSQL: Findings + Occurrences

### 4.1 Why PostgreSQL

The findings store needs rich queries for the triage UI that ScyllaDB
cannot efficiently provide:

| Query | ScyllaDB | PostgreSQL |
|-------|----------|------------|
| Filter by `rule_name` | Secondary index scatter | `WHERE` clause |
| Filter by multiple fields | Cannot combine indexes | Composite `WHERE` |
| Sort by `first_seen_at DESC` | Must be clustering key | `ORDER BY` |
| Aggregate (count by rule) | Not supported | `GROUP BY` |
| Join findings + occurrences | Not supported | `JOIN` |
| Full-text search on `location` | Not supported | `tsvector`/GIN |
| Paginate (offset-based) | Token-based only | `OFFSET/LIMIT` |

At 1-130 GB (findings + occurrences), PostgreSQL handles this without
partitioning.

### 4.2 Schema sketch

```sql
CREATE TABLE findings (
    finding_id      BYTEA PRIMARY KEY,  -- 32B, content-addressed
    tenant_id       BYTEA NOT NULL,
    stable_item_id  BYTEA NOT NULL,
    rule_fingerprint BYTEA NOT NULL,
    rule_name       TEXT NOT NULL,
    secret_hash     BYTEA NOT NULL,
    location        TEXT NOT NULL,
    triage_group_key BYTEA NOT NULL,
    first_seen_at   BIGINT NOT NULL,
    first_seen_run  BYTEA NOT NULL
);

CREATE TABLE occurrences (
    occurrence_id   BYTEA PRIMARY KEY,  -- 32B, content-addressed
    finding_id      BYTEA NOT NULL REFERENCES findings(finding_id),
    tenant_id       BYTEA NOT NULL,
    version_id      BYTEA NOT NULL,
    byte_offset     BIGINT NOT NULL,
    byte_length     BIGINT NOT NULL,
    first_seen_at   BIGINT NOT NULL,
    first_seen_run  BYTEA NOT NULL,
    shard_id        BIGINT NOT NULL
);

-- Triage UI indexes
CREATE INDEX idx_findings_tenant ON findings(tenant_id);
CREATE INDEX idx_findings_rule ON findings(tenant_id, rule_name);
CREATE INDEX idx_findings_triage ON findings(tenant_id, triage_group_key);
CREATE INDEX idx_findings_time ON findings(tenant_id, first_seen_at DESC);
CREATE INDEX idx_occurrences_finding ON occurrences(finding_id);
```

### 4.3 Idempotent upsert

Both `finding_id` and `occurrence_id` are content-addressed (BLAKE3).
Upsert is first-write-wins:

```sql
INSERT INTO findings (finding_id, ...) VALUES ($1, ...)
ON CONFLICT (finding_id) DO NOTHING;
```

No VACUUM pressure from conflicts -- `DO NOTHING` skips the write entirely
if the row exists.

### 4.4 Fence-epoch enforcement

Same pattern as the done-ledger: maintain a `fence_watermarks` table in
Postgres, check before batch write. The `FindingsSink` trait requires
independent per-shard fence watermarks.

---

## 5. Coordinator Progress Durability

The coordinator's in-process state (the materialized view of shard records)
uses a tiered durability model:

| Tier | Mechanism | Survives | Data loss window |
|------|-----------|----------|-----------------|
| 0 | In-memory only | Nothing (development) | Everything |
| 1 | ScyllaDB-backed (every write is an LWT) | Process crash, machine loss | Zero |

In the production ScyllaDB backend, every coordination write is an LWT
that is durable in ScyllaDB before the worker is ACK'd. There is no
separate "redb + periodic snapshot" layer -- ScyllaDB IS the durable store.

If the coordinator process crashes, it restarts and loads all state from
ScyllaDB. Workers detect unavailability (timeouts), wait, then re-acquire
their shards. The fence epoch bumps, old leases are invalid, and workers
resume from the last durably persisted cursor.

**Recovery time** depends on shard count:

| Shards | Data to load | Estimated recovery |
|--------|-------------|-------------------|
| 10K | ~5 MB | <1 second |
| 100K | ~50 MB | 1-3 seconds |
| 1M | ~500 MB | 5-15 seconds |

---

## 6. Findings Deduplication Safety Net

Re-scanning (due to coordinator restart, shard reassignment, or progress
regression) is safe because of three dedup layers:

1. **Done-ledger** checks before re-scanning (skip items marked `Scanned`).
2. **Content-addressed FindingId/OccurrenceId** -- same content always
   produces the same ID. `INSERT ... ON CONFLICT DO NOTHING` in Postgres.
3. **Commit protocol typestate** enforces ordering:
   findings durable -> done-ledger updated -> cursor advanced.

Re-scanning costs wasted compute, never produces duplicate findings.

---

## 7. Anti-Patterns to Avoid

These are drawn from the research and must not be violated during
implementation:

1. **Do NOT batch coordination writes and ACK before persistence.**
   Every `checkpoint()` ACK must be backed by a completed ScyllaDB LWT.
   Batching-then-ACK creates a lie window where the worker believes its
   progress is durable but it isn't.

2. **Do NOT use ScyllaDB row TTL for leases.** Leases are application-level
   timestamp comparisons (`now < deadline`). External TTL would create
   races between ScyllaDB's garbage collector and the coordinator's lease
   validation logic.

3. **Do NOT partition the done-ledger by ShardId.** `OvidHash` is not
   shard-dependent. Shard splits move items between shards, and a
   shard-local done-ledger would miss parent scan results.

4. **Do NOT use LWT for done-ledger writes.** The CRDT merge (Scanned
   absorbs Failed) is correctly handled by ScyllaDB's built-in LWW
   resolution via timestamp encoding. LWT would add Paxos overhead for
   no correctness benefit.

5. **Do NOT use cross-partition batches for `register_shards`.** ScyllaDB
   does not provide cross-partition atomicity. Use the saga pattern
   (Section 2.3) with the run status as the commit point.

6. **Do NOT use Postgres for the done-ledger.** 96-byte keys in a B-tree
   at 15 TB creates poor fanout (7-level tree), and 50K upserts/sec
   generates unsustainable VACUUM pressure.

---

## 8. Technology Rationale Summary

| Requirement | Why ScyllaDB | Why not Postgres |
|-------------|-------------|-----------------|
| 15 TB done-ledger | Shard-per-core, O(1) lookups | B-tree depth, VACUUM |
| CRDT merge | LWW timestamp trick (free) | `ON CONFLICT DO UPDATE` (dead tuples) |
| 100K point lookups/sec | 1.5M ops/sec/node | Adequate but wasteful |
| Coordination CAS | LWT (Paxos) | Viable but adds a 3rd system |

| Requirement | Why PostgreSQL | Why not ScyllaDB |
|-------------|---------------|-----------------|
| Filter/sort/aggregate | Native SQL | Not supported or scatter-gather |
| Join findings + occurrences | Native JOIN | Not supported |
| Full-text search | tsvector/GIN | Not supported |
| Ad-hoc triage queries | Arbitrary WHERE | Must pre-design query tables |

---

## 9. Open Questions

- **ScyllaDB deployment mode**: Self-hosted vs ScyllaDB Cloud. Cost
  tradeoff at 15 TB: $3-6K/month self-hosted vs $8-15K/month managed.
- **Postgres HA**: Patroni for automatic failover? Acceptable for
  findings (not on the hot path).
- **Done-ledger cleanup**: How to handle policy-generation rollover?
  Drop-and-recreate partition? TTL on entries older than N days?
- **Bloom filter optimization**: Application-level Bloom filter in front
  of ScyllaDB for the done-ledger? Saves network round-trips for items
  definitely not scanned. Adds memory cost (~1.2 GB per 1B entries at
  1% FPR).
