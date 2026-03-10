# Done-Ledger Postgres Review — Reference Findings

Static analysis audit of `crates/gossip-done-ledger-postgres` covering schema
design, index strategy, anticipated query patterns, migration runner safety,
and security posture. No live database was available; all findings are derived
from migration SQL, schema constants, type conversion code, and the
`DoneLedger` contract.

Date: 2026-03-09

---

## Resolved (applied in this review)

### R1 — `scanned_at` generated column removed

**Was**: `scanned_at BIGINT GENERATED ALWAYS AS (finished_at) STORED` — an
exact physical copy of `finished_at` costing 8 bytes/row (~800 MB per 100M
rows) with no semantic benefit beyond naming.

**Fix**: Dropped the generated column. The retention/scan-history index now
uses `finished_at` directly:

```sql
CREATE INDEX done_ledger_entries_tenant_policy_finished_at_idx
    ON done_ledger_entries (tenant_id, policy_hash, finished_at DESC, ovid_hash);
```

The `DONE_LEDGER_TENANT_POLICY_FINISHED_AT_INDEX` constant in `schema.rs`
documents that `finished_at` doubles as the logical "scanned_at" timestamp.

---

## Open Findings

### F1 — Retention index may benefit from `INCLUDE (status)`

**Severity**: WARN  
**Relevant tasks**: gossip-9006.3 (backend implementation), gossip-9006.4
(integration tests)

The retention index `(tenant_id, policy_hash, finished_at DESC, ovid_hash)`
cannot satisfy queries that filter or return `status` without a heap fetch.
If retention queries filter by status (e.g., "show only scanned entries"),
adding `status` as an `INCLUDE` column avoids O(matching_rows) random heap
reads:

```sql
CREATE INDEX done_ledger_entries_tenant_policy_finished_at_idx
    ON done_ledger_entries (tenant_id, policy_hash, finished_at DESC, ovid_hash)
    INCLUDE (status);
```

**Action**: Defer decision until `batch_get`/retention query shapes are
finalized in gossip-9006.3. If retention queries need `status`, add
`INCLUDE (status)` as a follow-up migration.

### F2 — Wide debug index on every row

**Severity**: INFO  
**Relevant tasks**: gossip-9006.3

The `run_shard_idx` index is 112 bytes/entry (8+8+32+32+32) across all rows.
At 100M rows that is ~11 GB of index storage for a debug-only access path.

**Alternatives**:

1. **Partial index** if debug lookups primarily inspect failures:
   ```sql
   CREATE INDEX done_ledger_entries_run_shard_failures_idx
       ON done_ledger_entries (run_id, shard_id, tenant_id, policy_hash, ovid_hash)
       WHERE status IN (1, 2, 3);
   ```
2. **On-demand creation** — create the index only when debugging, drop after.

**Action**: Acceptable for MVP. Document as droppable for space recovery at
scale. Revisit if storage becomes a concern.

### F3 — Migration runner cannot support `CREATE INDEX CONCURRENTLY`

**Severity**: WARN  
**Relevant tasks**: gossip-9006.3, gossip-9006.4

`apply_migrations` (`migrations.rs:107-116`) wraps all migrations in a single
transaction. PostgreSQL does not allow `CREATE INDEX CONCURRENTLY` inside a
transaction block.

When the crate needs to add indexes to a populated `done_ledger_entries`
table, the runner must support non-transactional migrations. Proposed design:

```rust
pub struct EmbeddedMigration {
    version: &'static str,
    sql: &'static str,
    /// Set to `false` for migrations containing `CREATE INDEX CONCURRENTLY`
    /// or other statements that cannot run inside a transaction.
    transactional: bool,
}
```

Non-transactional migrations would be applied outside the wrapping
transaction, with their own advisory lock and checksum recording.

**Action**: Not a problem today (initial empty table). Implement the
`transactional` flag when the first index-addition migration is needed.
gossip-9006.3 should document this limitation in the migration runner's
module docs.

### F4 — No `lock_timeout` before DDL in migration runner

**Severity**: WARN  
**Relevant tasks**: gossip-9006.3

The migration runner does not set `lock_timeout` before executing DDL. If
another connection holds a conflicting lock, the migration blocks
indefinitely and all subsequent connections queue behind it (lock queue
cascade).

```sql
SET lock_timeout = '5s';
```

**Action**: Add `SET lock_timeout` to the migration runner for safety.
Harmless for initial migration on an empty DB, but prevents runaway lock
waits for future migrations against populated tables. gossip-9006.3 should
include this in the backend's `apply_migrations` path.

### F5 — `NoTls` in `connect_and_apply_migrations`

**Severity**: WARN  
**Relevant tasks**: gossip-9006.3, gossip-9006.4

`connect_and_apply_migrations` (`migrations.rs:84`) uses `NoTls`. This is
documented as an MVP/integration-test convenience and is acceptable for now.

**Action**: gossip-9006.3 should either:
- Accept a TLS config parameter for production use, or
- Document the `NoTls` limitation clearly and plan a follow-up for TLS
  support before production deployment.

gossip-9006.4 integration tests can continue using `NoTls` for local
testcontainers.

---

## Query Pattern Guidance

The `DoneLedger` trait defines two operations. These are the recommended SQL
shapes for gossip-9006.3 to implement.

### `batch_get` — PK point lookup

```sql
SELECT tenant_id, policy_hash, ovid_hash, status, bytes_scanned,
       findings_count, fence_epoch, started_at, finished_at,
       run_id, shard_id, error_code
FROM done_ledger_entries
WHERE tenant_id = $1 AND policy_hash = $2 AND ovid_hash = ANY($3::bytea[])
```

- Uses the PK B-tree via equality on all three leading columns.
- `ANY($3::bytea[])` handles batch lookups without `SELECT *`.
- Returns positional alignment by joining results back to input order in Rust.
- Avoid `SELECT *` — explicitly list columns to enable future index-only scans
  and prevent breakage if columns are added.

### `batch_upsert` — monotonic lattice merge

```sql
INSERT INTO done_ledger_entries
    (tenant_id, policy_hash, ovid_hash, status, bytes_scanned,
     findings_count, fence_epoch, started_at, finished_at,
     run_id, shard_id, error_code)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (tenant_id, policy_hash, ovid_hash) DO UPDATE
SET status         = EXCLUDED.status,
    bytes_scanned  = GREATEST(done_ledger_entries.bytes_scanned, EXCLUDED.bytes_scanned),
    findings_count = CASE
        WHEN EXCLUDED.status > done_ledger_entries.status
        THEN EXCLUDED.findings_count
        WHEN EXCLUDED.status = done_ledger_entries.status
        THEN GREATEST(done_ledger_entries.findings_count, EXCLUDED.findings_count)
        ELSE done_ledger_entries.findings_count
    END,
    fence_epoch    = EXCLUDED.fence_epoch,
    started_at     = EXCLUDED.started_at,
    finished_at    = EXCLUDED.finished_at,
    run_id         = EXCLUDED.run_id,
    shard_id       = EXCLUDED.shard_id,
    error_code     = EXCLUDED.error_code
WHERE EXCLUDED.status > done_ledger_entries.status
   OR (EXCLUDED.status = done_ledger_entries.status
       AND (EXCLUDED.finished_at > done_ledger_entries.finished_at
            OR (EXCLUDED.finished_at = done_ledger_entries.finished_at
                AND EXCLUDED.started_at > done_ledger_entries.started_at)));
```

**Critical considerations** (from gossip-9006.3 task description):

- A status-winner-only upsert is **not sufficient**. The conformance harness
  checks that `bytes_scanned` and `findings_count` do not regress after
  fail-then-scan or scan-then-fail sequences.
- The in-memory merge in `crates/gossip-persistence-inmemory/src/done_ledger.rs:327-400`
  is the behavioral source of truth, not the simplified phase-3 artifact.
- The `WHERE` clause ensures no-ops for lower or equal status (preventing
  unnecessary row locks and WAL writes).
- For multi-row batches, use `UNNEST` arrays or a `VALUES` list with a single
  `INSERT ... ON CONFLICT`.

**Anti-pattern**: Do NOT implement the lattice merge as SELECT-then-INSERT in
Rust. That introduces a TOCTOU race between concurrent writers. The
`ON CONFLICT ... WHERE` pattern is atomic within a single row.

**Alternative**: If SQL merge complexity is too high, gossip-9006.3 task
description allows Option A (read existing, merge in Rust, write back). This
is acceptable for MVP if done within a transaction with row-level locking.

---

## Schema Strengths (no action needed)

These are confirmed-correct design decisions that should be preserved:

| Item | Evidence |
|------|----------|
| `BYTEA CHECK(octet_length = 32)` for identity columns | Matches 32-byte BLAKE3 hashes from `define_id_32!` |
| `SMALLINT CHECK(IN(1,2,3,10,11))` for status | Matches `DoneLedgerStatus` discriminants exactly |
| `BIGINT CHECK(>= 0)` for ordered counters | Preserves SQL ordering for non-negative u64 values |
| `BIGINT` bit-pattern mode for `run_id`/`shard_id` | Full u64 domain via two's-complement reinterpretation |
| `finished_at >= started_at` cross-field CHECK | Mirrors `DoneLedgerProvenance::new()` debug_assert |
| `status_shape_ck` multi-column CHECK | Mirrors `DoneLedgerRecord::validate()` at the DB level |
| `error_code` bounded to 1-128 bytes | Matches `MAX_DONE_LEDGER_ERROR_CODE_SIZE` |
| `TIMESTAMPTZ` on migration table `applied_at` | Correct timezone-aware type |
| `pg_advisory_xact_lock` for migration serialization | Transaction-scoped, auto-releases on commit/rollback |
| BLAKE3 checksum verification on migrations | Detects in-place edits to already-applied SQL |
| Parameterized queries throughout | No SQL injection vectors |

---

## Capacity Planning Notes

| Component | Per-row cost | At 100M rows | At 1B rows |
|-----------|-------------|-------------|------------|
| PK index (96 B/key) | ~96 B | ~9.6 GB | ~96 GB |
| Retention index (104 B/entry) | ~104 B | ~10.4 GB | ~104 GB |
| Debug index (112 B/entry) | ~112 B | ~11.2 GB | ~112 GB |
| Heap tuple (all columns) | ~180 B est. | ~18 GB | ~180 GB |
| **Total estimated** | ~492 B | **~49 GB** | **~490 GB** |

At scale (>100M rows), the debug index is the first candidate for
reclamation. Autovacuum scale factor should be reduced from the default
0.2 to 0.01-0.02 for tables of this size.
