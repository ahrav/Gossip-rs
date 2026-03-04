# Boundary 5 - Persistence Architecture

> **Status: Design spec + partial implementation.**
> The Rust trait surface (`DoneLedger`, `FindingsSink`, `PageCommit<S>`,
> and supporting types) is defined in staged artifacts under
> `tmp/gossip-project-artifacts/boundary_5_chunk_{1..5}.rs` and
> documented in the module doc at
> `crates/gossip-contracts/src/persistence/mod.rs`.
> The external storage backends (etcd, ScyllaDB, PostgreSQL) described
> in sections 2–4 are **aspirational design targets** — no production
> backend implementations exist yet. The coordination backend trait
> lives in `gossip-coordination` as `CoordinationBackend`
> (`crates/gossip-coordination/src/traits.rs`).

Boundary 5 defines the durable storage plan for three subsystems:

- Coordination state (runs, shards, leases, fences, cursors, split state)
- Done-ledger (dedupe index: “was this object-version scanned under this policy?”)
- Findings store (triage/query plane: findings + occurrences)

This is the normative reference for production persistence backends behind:

- Coordination: `CoordinationBackend` (trait in `gossip-coordination/src/traits.rs`) + `PageCommit<S>` (worker commit protocol)
- Done-ledger: `DoneLedger`
- Findings: `FindingsSink`

Non-negotiables (project-wide):

- Never store or emit raw secret bytes (DB rows, logs, metrics, traces, errors, tests).
- Determinism: same bytes + same policy => same IDs and outputs.
- Idempotency: assume at-least-once execution; sinks dedupe by deterministic IDs.
- Multi-tenant isolation is correctness: strict tenant namespaces, explicit authz checks.

---

## Planned Rust types

> **Note:** The types below are design-time artifacts defined in staged
> files (`tmp/gossip-project-artifacts/boundary_5_chunk_{1..5}.rs`). They
> do not exist as compiled code in any workspace crate. The module doc
> placeholder lives at `crates/gossip-contracts/src/persistence/mod.rs`.
> No production backend implementations exist yet; only in-memory test
> doubles (behind `test-support` feature flag).

### Traits

| Trait | Purpose | Key methods |
|-------|---------|-------------|
| `DoneLedger` | Dedupe index: "was this object-version scanned under this policy?" | `batch_get(&self, &DoneLedgerGetBatch, LogicalTime) -> Result<DoneLedgerGetResult, DoneLedgerGetError>`, `batch_upsert(&self, &DoneLedgerUpsertBatch, ShardId, FenceEpoch, LogicalTime) -> Result<(), DoneLedgerUpsertError>` |
| `FindingsSink` | Triage/query plane: findings + occurrences persistence | `upsert_findings(&self, &FindingsUpsertBatch, ShardId, FenceEpoch, LogicalTime) -> Result<FindingsUpsertResult, FindingsUpsertError>` |
| `CoordinationBackend` | Shard lifecycle: acquire, checkpoint, complete, park, split (lives in `gossip-coordination/src/traits.rs`, not in this module) | `acquire_and_restore_into`, `checkpoint`, `complete`, `park_shard`, `split_residual`, `split_replace` |

### Typestate machine

| Type | Purpose |
|------|---------|
| `PageCommit<S>` | Compile-time enforcement of the commit protocol ordering: findings flush → done-ledger upsert → cursor checkpoint. State parameter `S` transitions through `Pending` → `FindingsFlushed` → `LedgerCommitted` → `CommitProof`. |

### Data types

| Type | Purpose |
|------|---------|
| `DoneLedgerKey` | Composite lookup key: `(TenantId, PolicyHash, OvidHash)` — 96-byte fixed-width. |
| `OvidHash` | Content-addressed Object-Version Identity digest (BLAKE3, 32 bytes). Derived from `OvidInputs` via `derive_ovid_hash`. |
| `DoneLedgerStatus` | Scan outcome enum with monotonic join-semilattice semantics: `NotSeen < Failed < Scanned`. |
| `DoneLedgerEntry` | Stored entry: status + metadata (scanned_at, run_id, shard_id). |
| `DoneLedgerLookup` | Query result per key: `NotSeen` or `Found(DoneLedgerEntry)`. |
| `DoneLedgerGetBatch` / `DoneLedgerGetResult` | Batch query request/response containers. |
| `DoneLedgerUpsertItem` / `DoneLedgerUpsertBatch` | Batch upsert request containers. |
| `FindingRecord` | Detection finding with content-addressed `FindingId`, tenant, rule, secret hash, location (never raw secrets). |
| `OccurrenceRecord` | Version-specific sighting of a finding: byte offset/length, version_id, shard provenance. |
| `FindingsUpsertBatch` | Capacity-bounded batch of findings + occurrences for atomic upsert. |
| `FindingsUpsertResult` | Upsert outcome counts: inserted vs. deduplicated for findings and occurrences. |

### Test doubles (`test-support` feature)

| Type | Implements | Notes |
|------|-----------|-------|
| `InMemoryDoneLedger` | `DoneLedger` | `HashMap`-backed. Tracks fence watermarks per shard. Not thread-safe. |
| `InMemoryFindingsSink` | `FindingsSink` | `HashMap`-backed. First-write-wins dedup. Not thread-safe. |

---

## 0. Summary of decisions (design targets)

### Storage topology (recommended — not yet implemented)

| Subsystem                                               | Store          | Why                                                                                                                              |
| ------------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Coordination (runs/shards/leases/fences/cursors/splits) | **etcd**       | Small state (O(shards)), linearizable transactions, leases, proven fencing patterns. Avoids LWT hot-partition throughput cliffs. |
| Done-ledger (dedupe KV)                                 | **ScyllaDB**   | Massive KV scale (10^8–10^11 entries), high-throughput point reads/writes, predictable cost.                                     |
| Findings + occurrences (triage query plane)             | **PostgreSQL** | Rich queries: filter/sort/join/aggregate + optional full-text on safe display fields.                                            |

Total external systems: 3 (etcd + ScyllaDB + PostgreSQL).

If “2 systems” is mandatory, see Appendix A.

---

## 1. Scale targets

| Parameter                  |                    Value | Notes                                               |
| -------------------------- | -----------------------: | --------------------------------------------------- |
| Minimum shard size         |                  5–10 GB | Smaller shards can kill throughput due to overhead. |
| Scanner throughput         | 100–3000 MB/s per worker | Connector-dependent.                                |
| Active shards (concurrent) |               200–10,000 | Fleet dependent.                                    |
| Total shards (PB scale)    |                  100K–1M | Coordination state is O(shards).                    |
| Checkpoint writes/sec      |                 40–2,000 | Assuming 5-second checkpoint interval.              |
| Done-ledger entries        |                100M–100B | 15 GB–15 TB (order-of-magnitude).                   |
| Findings                   |                  1M–100M | Query-plane scale.                                  |
| Occurrences                |                  5M–500M | Query-plane scale.                                  |

Checkpoint write math (sanity):

- 200 active shards / 5s = 40 checkpoints/sec
- 10,000 active shards / 5s = 2,000 checkpoints/sec

---

## 2. Coordination persistence (etcd) — design target

### 2.1 Why etcd

Coordination requires:

- Linearizable compare-and-swap (CAS) for fenced mutations.
- Atomic multi-key updates for shard splits (bounded fanout).
- Lease TTL semantics for liveness and rapid reassignment.
- Strong fencing: stale owners must not checkpoint/split/complete/park.

This matches the Phase I coordination contract approach (lease + fencing token + CAS/txn).

### 2.2 Keyspace layout

All values are versioned blobs (e.g., `v1` prefix + stable serialization). No raw secret bytes.

Durable records:

- `/gossip/v1/tenants/{tenant_id}/runs/{run_id}` -> `RunRecord`
- `/gossip/v1/tenants/{tenant_id}/runs/{run_id}/shards/{shard_id}` -> `ShardRecord`

Ephemeral ownership keys (attached to the worker’s etcd lease):

- `/gossip/v1/tenants/{tenant_id}/runs/{run_id}/shards/{shard_id}/owner` -> `{worker_id, fence_epoch}`

Optional pull-friendly indexes (avoid scanning everything):

- `/gossip/v1/tenants/{tenant_id}/runs_active/{run_id}` -> empty value
- `/gossip/v1/tenants/{tenant_id}/runs/{run_id}/shards_active/{shard_id}` -> empty value

Ownership invariant (required):

- A worker is the valid owner of a shard iff the `/owner` key exists, matches `worker_id`, and the shard’s `fence_epoch` equals the value stored in the owner key.

### 2.3 ShardRecord fields (normative)

Minimum required fields (exact struct lives in contracts; storage must persist these):

- `status` (Active / Parked / Done / Split / etc.)
- `fence_epoch` (monotonic, increments on each successful acquire)
- `cursor` (last_key + token + semantics)
- `spec` (key-range start/end + metadata/hints)
- `parent_shard_id` (optional)
- `spawned_shard_ids` (bounded list or compact encoding)
- bounded `op_log` for idempotency (ring buffer; size is a contract)

### 2.4 Operation mapping (etcd transactions)

All coordination mutations must be:

- fenced: require correct `(worker_id, expected_fence_epoch)`
- idempotent: require stable `op_id` and a bounded `op_log`

Common txn preconditions:

- owner key exists and matches worker
- `ShardRecord.fence_epoch == expected`
- `ShardRecord.status` allows the operation
- `op_id` not already present with different payload hash (idempotency)

Operations:

#### `acquire_and_restore_into`

Effects must be atomic:

- Create `/owner` key attached to the worker’s etcd lease
- Bump `ShardRecord.fence_epoch = fence_epoch + 1`
- Set/confirm `ShardRecord.status = Active` (if reacquiring from expired lease)
- Append `op_log` entry for acquire

#### `checkpoint` (hot path)

Single txn:

- Preconditions: owner key exists + fence matches + shard Active
- Effects: update cursor (monotonic), append op_log entry

Hard rule:

- Do not ACK a checkpoint to the worker until the etcd txn commits.

#### `complete` / `park_shard`

Single txn:

- Preconditions: owner key exists + fence matches + shard Active
- Effects: set terminal status, set park reason if applicable, update indexes

#### `split_residual` (preferred: bounded atomicity)

Single txn:

- Preconditions: owner key exists + fence matches + parent Active
- Effects:
  - Rewrite parent spec to smaller range
  - Create one child shard record (Active)
  - Record child id on parent
  - Append op_log entry

#### `split_replace` (terminal parent)

Single txn:

- Preconditions: owner key exists + fence matches + parent Active
- Effects:
  - Set parent status = Split
  - Create N children shard records (Active)
  - Record child ids on parent
  - Append op_log entry

### 2.5 Split fanout limits (required)

etcd transactions are bounded in size and operation count. Therefore:

- `split_replace` must enforce `max_children_per_op` (default 2–8).
- Large connector-proposed splits must be implemented as iterative residual splits or multiple small replace splits.
- Atomicity requirement: never publish a partially created children set as “the split result.”

### 2.6 Run creation + shard registration (saga with explicit commit point)

Goal: workers must not see partially registered runs.

Plan:

1. Create `RunRecord` with `status = Initializing` (CAS if-not-exists)
2. Write shard records (unconditional puts) in bounded chunks
3. Commit txn:
   - compare `RunRecord.status == Initializing`
   - set `status = Active`
   - create `/runs_active/{run_id}` index key
4. Workers enumerate only runs present in `/runs_active/`

Orphan cleanup:

- GC `Initializing` runs older than `N` hours by deleting run + shard key prefixes.

### 2.7 Load and sizing notes (not hand-wavy)

You must benchmark the exact etcd txn shapes (payload size, compares, updates, op_log mutation) under realistic concurrency.

Allowed tuning knobs:

- checkpoint interval (time or item-count based)
- op_log size (bounded)
- cursor encoding size (bounded)

Not allowed:

- batching coordination writes and ACKing before persistence (creates a “lie window”).

---

## 3. Done-ledger persistence (ScyllaDB) — design target

### 3.1 What the done-ledger guarantees

The done-ledger answers:

- Has `(tenant_id, policy_hash, ovid_hash)` been committed as scanned?
- If yes, skip rescanning that object-version for that tenant+policy.

Key:

- `DoneLedgerKey = tenant_id[32] || policy_hash[32] || ovid_hash[32]` (BLAKE3-derived components)

Value (minimal):

- `status` (Failed < Scanned)
- `scanned_at` (logical time)
- `run_id`, `shard_id` (debug/traceability)

### 3.2 Schema (bounded partitions, avoids unbounded wide partitions)

Do not use `(tenant_id, policy_hash)` alone as a partition key at large scale.

Use bucketing:

- `bucket = prefix_bits(ovid_hash, BUCKET_BITS)` (configurable)

Recommended starting point:

- `BUCKET_BITS = 16` (65,536 buckets)
- Adjust based on observed largest-tenant distribution and row size.

Schema:

```sql
CREATE TABLE done_ledger.entries (
    tenant_id   blob,
    policy_hash blob,
    bucket      smallint,
    ovid_hash   blob,

    status      tinyint,
    scanned_at  bigint,
    run_id      blob,
    shard_id    bigint,

    PRIMARY KEY ((tenant_id, policy_hash, bucket), ovid_hash)
);
```

Batch strategy:

- Group batch keys by `(tenant_id, policy_hash, bucket)`
- Issue batched point reads/writes per bucket
- Use bounded concurrency across buckets

### 3.3 Merge semantics (Failed vs Scanned)

Required lattice property:

- `Scanned` absorbs `Failed` (no regression)

Two options:

#### Option A (recommended): LWW timestamp encoding

Encode status into the CQL write timestamp:

- `ts = (status_discriminant << 56) | logical_time_us`

Constraints:

- `logical_time_us < 2^56` microseconds
  - `2^56` microseconds is ~2,283 years, so overflow is not a practical concern
- Every write must specify `USING TIMESTAMP`; forgetting it is a correctness bug.

This yields:

- Scanned always “wins” over Failed regardless of arrival order (no LWT).

Operational guardrails (required):

- A single library API must generate timestamps and perform writes.
- A test must fail if any write path omits `USING TIMESTAMP`.

#### Option B: LWT merge

Use conditional updates to prevent regression.

- Higher latency and lower throughput
- Simpler to reason about than timestamp tricks
- Only choose this if Option A becomes too footgun-prone in practice

This document selects Option A, with strict wrapper enforcement.

### 3.4 Retention and policy rollover (required decision)

Policy changes create new `policy_hash`, so correctness does not require deleting old entries.

Storage will grow without a retention plan. Supported strategies:

- Keep last `N` policy_hash values per tenant (delete older by range scan and bucket iteration)
- TTL-based retention (accept tombstones + compaction cost)
- Offline archive then delete (export to object storage)

Pick one per deployment and document it as a configuration.

---

## 4. Findings persistence (PostgreSQL) — design target

### 4.1 Requirements

Findings store supports the triage UI:

- filter by rule, time, tenant, policy, asset scope
- join findings to occurrences
- aggregate counts and trends
- optional full-text search on safe display fields

Hard rule:

- never store raw secret bytes, even in “context snippets”

### 4.2 Identifiers and fields

IDs are content-addressed (BLAKE3 domain-separated per contracts). Inserts must be idempotent.

Findings must include at minimum:

- `tenant_id`, `policy_hash`
- `rule_id`, `rule_name` (for display and grouping)
- `ovid_hash`, `stable_item_id`
- `secret_hash` (never raw secret)
- `evidence_hash` (never raw secret)
- `first_seen_at`, `last_seen_at`, plus run IDs for provenance
- safe location display field(s) only

### 4.3 Schema (minimal + query indexes)

```sql
CREATE TABLE findings (
    finding_id      BYTEA PRIMARY KEY,

    tenant_id       BYTEA NOT NULL,
    policy_hash     BYTEA NOT NULL,

    rule_id         BYTEA NOT NULL,
    rule_name       TEXT  NOT NULL,

    ovid_hash       BYTEA NOT NULL,
    stable_item_id  BYTEA NOT NULL,

    secret_hash     BYTEA NOT NULL,
    evidence_hash   BYTEA NOT NULL,

    -- Safe display only (redacted/normalized, never secret bytes)
    location_safe   TEXT NOT NULL,

    first_seen_at   BIGINT NOT NULL,
    last_seen_at    BIGINT NOT NULL,

    first_seen_run  BYTEA NOT NULL,
    last_seen_run   BYTEA NOT NULL
);

CREATE TABLE occurrences (
    occurrence_id   BYTEA PRIMARY KEY,

    finding_id      BYTEA NOT NULL REFERENCES findings(finding_id),

    tenant_id       BYTEA NOT NULL,
    policy_hash     BYTEA NOT NULL,

    version_id      BYTEA NOT NULL,

    byte_offset     BIGINT NOT NULL,
    byte_length     BIGINT NOT NULL,

    seen_at         BIGINT NOT NULL,
    run_id          BYTEA NOT NULL,
    shard_id        BIGINT NOT NULL
);

-- Indexes for triage
CREATE INDEX idx_findings_tenant_time   ON findings(tenant_id, first_seen_at DESC);
CREATE INDEX idx_findings_tenant_rule   ON findings(tenant_id, rule_name);
CREATE INDEX idx_findings_tenant_policy ON findings(tenant_id, policy_hash);

CREATE INDEX idx_occ_finding            ON occurrences(finding_id);
CREATE INDEX idx_occ_tenant_policy      ON occurrences(tenant_id, policy_hash);

-- Optional: full-text on location_safe
-- Add a generated tsvector column + GIN index when needed.
```

### 4.4 Idempotent inserts

First-write-wins:

```sql
INSERT INTO findings (...) VALUES (...)
ON CONFLICT (finding_id) DO NOTHING;

INSERT INTO occurrences (...) VALUES (...)
ON CONFLICT (occurrence_id) DO NOTHING;
```

Updates:

- If you want `last_seen_at` to advance, use an update that is monotonic:
  - `last_seen_at = GREATEST(last_seen_at, EXCLUDED.last_seen_at)`
  - but keep it bounded and avoid turning every insert into a hot update path.

---

## 5. Cross-subsystem commit ordering (correctness-critical)

The worker-side commit protocol is mandatory and enforces correctness without cross-store transactions:

1. Findings durable (Postgres)
2. Done-ledger durable (Scylla)
3. Only then emit `ItemCommitted` enabling cursor checkpoint (etcd)

Consequences:

- If done-ledger says “Scanned,” findings are already durable.
- Cursor never advances beyond what has been durably committed.
- Retries and reassignment are safe: idempotent sinks dedupe by deterministic IDs.

---

## 6. Recovery and failure behavior

- Coordination is authoritative for ownership and cursor.
- Done-ledger and findings are idempotent sinks; duplicates are safe.

Lease loss rule (hard):

- If a worker cannot renew its etcd lease or loses the `/owner` key, it must stop scanning and must not checkpoint/split/complete/park.

Coordinator restart:

- Reload state from etcd via prefix scans + indexes.
- Workers reacquire shards, `fence_epoch` bumps, and resume from last durable cursor.

---

## 7. Anti-patterns (must not ship)

1. Do not ACK checkpoints before the coordination txn commits.
2. Do not implement coordination on a design that serializes hot fenced writes onto a single key/partition.
3. Do not create unbounded wide partitions for the done-ledger.
4. Do not store raw secret bytes in Postgres (including snippets). Store hashes and safe display fields only.
5. Do not partition done-ledger by shard id (ledger key is shard-independent).
6. Do not allow unbounded split fanout. Enforce `max_children_per_op`.

---

## 8. Implementation plan (what to build next)

### 8.1 Coordination backend (etcd)

- Implement the full Phase I contract:
  - acquire with fence bump
  - checkpoint/complete/park with fencing
  - atomic split operations with bounded fanout
- Tests (required):
  - property tests: no-overlap + no-gaps under churn
  - deterministic simulation: crashes/retries/partitions/kv delays
  - stale-fence rejection for all coordination writes
  - atomic split publication under failures

### 8.2 Done-ledger backend (Scylla)

- Implement:
  - batch get (bucket-grouped)
  - batch upsert with CRDT merge semantics (Option A)
- Tests (required):
  - out-of-order writes converge (Failed then Scanned, Scanned then Failed)
  - timestamp encoding always applied (no default timestamp path)
  - policy hash isolation (policy rollover does not cause false skips)
- Benchmark:
  - per-tenant hot workload
  - partition size distribution by bucket count

### 8.3 Findings backend (Postgres)

- Implement:
  - idempotent insert path (and optional monotonic last_seen updates)
  - indexes for triage queries
- Tests (required):
  - deterministic ID dedupe under retries and overlap
  - “no secrets in DB rows” redaction tests (systematic)

### 8.4 End-to-end commit protocol gates

- Prove via deterministic simulation:
  - findings -> ledger -> cursor ordering
  - crashes between stages never produce cursor advancement without durable sinks
  - retries never create duplicates

---

## 9. Open questions

- etcd cluster sizing vs checkpoint rate targets (benchmark-driven).
- Done-ledger retention policy selection (TTL vs keep-last-N policy hashes vs offline archive).
- Findings partitioning policy if retention windows become multi-year at high volume.
- Whether to add an in-process Bloom filter in front of done-ledger (requires careful sizing and eviction; not correctness-critical).

---

## Appendix A - If “2 systems” is mandatory

Two realistic options:

1. Postgres for coordination + findings; Scylla for done-ledger

- Coordination becomes transactional and simple.
- Done-ledger stays scalable KV.
- You still keep strong fencing and atomic splits via SQL transactions.

2. DynamoDB for coordination + done-ledger; Postgres for findings

- Works well on AWS (conditional writes + TTL), but changes deployment assumptions.
- Requires careful modeling for atomic split publication.

Not recommended:

- Scylla for coordination + done-ledger: high coordination throughput risk unless you accept substantial complexity (transaction records, reconciliation state machines) and prove it with simulation/property tests.
