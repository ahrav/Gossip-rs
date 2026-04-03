---
name: postgres-review
description: Use when designing or auditing PostgreSQL schemas, reviewing migrations for lock safety, investigating query performance, or optimizing indexes and partitioning. Connects to the database for concrete evidence via EXPLAIN ANALYZE and pg_stat_* views.
---

# PostgreSQL Review & Tuning

Audit and optimize PostgreSQL schemas, queries, indexes, partitioning, and
configuration. Every recommendation must be backed by concrete evidence gathered
from the live database — never guess when you can measure.

## When to Use

- After adding or modifying tables, columns, indexes, or constraints
- After writing new queries or changing existing ones
- When investigating slow queries, lock contention, or bloat
- Before merging any PR that touches migrations or query modules
- When designing partitioning strategies for large tables
- When reviewing connection pooling, vacuum settings, or replication config
- When auditing security (RLS policies, role permissions, SSL)
- Periodically as dataset grows to catch regressions

## Prerequisites

Determine the connection method:

```bash
# Check for psql availability.
psql --version

# Common connection patterns:
psql -h localhost -U postgres -d mydb
psql "$DATABASE_URL"

# Docker:
docker exec -it <container> psql -U postgres -d mydb
```

Record the PostgreSQL version — it determines available features (v11+ instant
ADD COLUMN defaults, v12+ NOT NULL via CHECK optimization, v13+ deduplication,
v14+ bottom-up index deletion, v16+ improved partition pruning for prepared
statements).

If no live database is available, create a temporary one with the schema under
review and populate with synthetic data so that EXPLAIN ANALYZE and pg_stat_*
views return meaningful results.

For detailed anti-patterns, index selection guidance, migration lock-level
reference, monitoring queries, and configuration tuning baselines, consult
`references/postgres-knowledge-base.md`.

## Workflow

### Phase 1 — Collect Baseline Metrics

Gather facts before proposing any changes. Run these against the live database.

```sql
-- 1. Version and key settings.
SELECT version();
SHOW shared_buffers;
SHOW effective_cache_size;
SHOW work_mem;
SHOW maintenance_work_mem;
SHOW random_page_cost;
SHOW max_connections;

-- 2. Database size.
SELECT pg_size_pretty(pg_database_size(current_database()));

-- 3. Top 20 tables by total size.
SELECT schemaname || '.' || relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       pg_size_pretty(pg_relation_size(relid)) AS table_size,
       pg_size_pretty(pg_total_relation_size(relid) - pg_relation_size(relid)) AS index_size,
       n_live_tup AS row_estimate
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 20;

-- 4. Cache hit ratio.
SELECT round(100.0 * sum(heap_blks_hit) /
       NULLIF(sum(heap_blks_hit) + sum(heap_blks_read), 0), 2) AS cache_hit_pct
FROM pg_statio_user_tables;

-- 5. Table bloat indicators (dead tuples, vacuum status).
SELECT schemaname, relname, n_live_tup, n_dead_tup,
       round(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC LIMIT 20;

-- 6. XID wraparound distance.
SELECT datname, age(datfrozenxid) AS xid_age,
       round(100.0 * age(datfrozenxid) / 2000000000, 2) AS pct_to_wraparound
FROM pg_database WHERE datallowconn;

-- 7. Connection state distribution.
SELECT state, count(*) FROM pg_stat_activity GROUP BY state;
```

Record all output as the baseline.

### Phase 2 — Schema Review

Read migration files or DDL source, then check each item:

#### Checklist

- [ ] **Data types**: `uuid` for IDs (not `varchar(36)`), `timestamptz` (not
      `timestamp`), `bigint` for large counters, `text` over `varchar(n)`
      unless constraint needed, `jsonb` (not `json`), `inet`/`cidr` for IPs.
- [ ] **Primary keys**: Every table has a PK. Prefer
      `bigint GENERATED ALWAYS AS IDENTITY` or `uuid` over `serial`.
- [ ] **NOT NULL constraints**: Every column that must never be NULL has the
      constraint. Missing NOT NULL on a FK column is a bug.
- [ ] **Foreign keys**: All FK references exist with appropriate ON DELETE.
      **FK columns must be indexed** (PostgreSQL does NOT auto-index FKs).
- [ ] **Check constraints**: Domain constraints at DB level — status enums,
      positive amounts, valid ranges.
- [ ] **Defaults**: Sensible defaults for timestamps (`now()`), status columns.
- [ ] **Naming**: Consistent snake_case. Index names: `idx_<table>_<columns>`.

```sql
-- Find FK columns without indexes (most common PostgreSQL performance mistake).
SELECT c.conrelid::regclass AS table_name,
       c.conname AS fk_name,
       a.attname AS column_name
FROM pg_constraint c
JOIN pg_attribute a ON a.attnum = ANY(c.conkey) AND a.attrelid = c.conrelid
WHERE c.contype = 'f'
  AND NOT EXISTS (
      SELECT 1 FROM pg_index i
      WHERE i.indrelid = c.conrelid
        AND a.attnum = ANY(i.indkey)
  );
```

### Phase 3 — Index Analysis

For every important query, run EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) and
verify the planner uses expected indexes.

#### Process

1. **List all SQL strings** in query modules.
2. **For each**, run EXPLAIN (ANALYZE, BUFFERS) with representative data.
3. **Flag** sequential scans (`Seq Scan`) on tables with >10K rows.
4. **Flag** sorts spilling to disk (`Sort Method: external merge`).
5. **Flag** nested loops with high row counts suggesting missing index.
6. **Flag** unused indexes costing write performance.

**Critical**: Multiply actual time by `loops` to get true total time. Check
estimated vs actual rows — large divergence means stale stats or correlated
columns needing `CREATE STATISTICS`.

```sql
-- Unused indexes (non-unique, non-PK, zero scans).
SELECT schemaname || '.' || indexrelname AS index,
       pg_size_pretty(pg_relation_size(indexrelid)) AS size,
       idx_scan AS scans
FROM pg_stat_user_indexes
JOIN pg_index USING (indexrelid)
WHERE NOT indisunique AND NOT indisprimary AND idx_scan < 50
ORDER BY pg_relation_size(indexrelid) DESC;

-- Duplicate indexes.
SELECT pg_size_pretty(sum(pg_relation_size(idx))::bigint) AS size,
       array_agg(idx) AS indexes
FROM (
    SELECT indexrelid::regclass AS idx,
           (indrelid::text || E'\n' || indclass::text || E'\n' ||
            indkey::text || E'\n' || coalesce(indexprs::text, '') ||
            E'\n' || coalesce(indpred::text, '')) AS key
    FROM pg_index
) sub GROUP BY key HAVING count(*) > 1
ORDER BY sum(pg_relation_size(idx)) DESC;

-- Invalid indexes (from failed CREATE INDEX CONCURRENTLY).
SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid;
```

#### Index Type Selection

| Data Pattern | Index Type | Use When |
|---|---|---|
| Equality, range, ORDER BY | **B-tree** (default) | Most queries |
| Full-text search, JSONB containment, arrays | **GIN** | `@>`, `@@`, `&&` operators |
| Geospatial, range types, exclusion constraints | **GiST** | `&&`, `@>`, KNN |
| Time-series, append-only, high-correlation data | **BRIN** | Correlation > 0.9, huge tables |
| Partial subset queries (`WHERE active = true`) | **Partial index** | Small active subset |
| Index-only scan with extra columns | **Covering (INCLUDE)** | SELECT cols beyond key |
| Queries on expressions (`lower(email)`) | **Expression index** | Function in WHERE |

### Phase 4 — Query Tuning

For queries identified as suboptimal in Phase 3:

1. **Rewrite** the query or **add/modify** an index.
2. **Re-run** EXPLAIN (ANALYZE, BUFFERS) to confirm improvement.
3. **Compare** actual times and buffer hits before vs. after.

#### Common Anti-Patterns

| Pattern | Problem | Fix |
|---|---|---|
| `SELECT *` | Prevents index-only scans | Select only needed columns |
| `OFFSET N` pagination | Scans and discards N rows | Keyset pagination (`WHERE id > last_id`) |
| `NOT IN (subquery)` | NULL handling, poor plans | `NOT EXISTS` |
| `LIKE '%prefix'` | Leading wildcard, no index | Trigram index (`pg_trgm`) |
| `jsonb ->> 'key' = 'val'` | No index on expression | Expression index on jsonb path |
| `lower(email) = ...` | Function on indexed column | Expression index on `lower(email)` |
| `COUNT(*)` on huge table | Full scan | Approximate via `reltuples` for UI |
| Implicit type casts | `WHERE int_col = '123'` | Match types to prevent cast |
| CTE as optimization fence | Pre-v12 materialization | Use subquery or `NOT MATERIALIZED` |
| Large `IN (...)` lists | Plan bloat | `= ANY(ARRAY[...])` or temp table |

### Phase 5 — Partitioning Review

For tables exceeding ~10M rows or with clear time-series/tenant access patterns.

```sql
-- Partitioning candidates.
SELECT relname, n_live_tup,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_stat_user_tables WHERE n_live_tup > 1000000
ORDER BY n_live_tup DESC;

-- Existing partitions.
SELECT parent.relname AS parent, child.relname AS partition,
       pg_get_expr(child.relpartbound, child.oid) AS bound,
       pg_size_pretty(pg_relation_size(child.oid)) AS size
FROM pg_inherits
JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
JOIN pg_class child ON pg_inherits.inhrelid = child.oid
ORDER BY parent.relname, child.relname;
```

#### Checklist

- [ ] **Strategy**: RANGE (time-series), LIST (tenant/status), HASH (even distribution)?
- [ ] **Partition key**: Appears in most WHERE clauses? Enables pruning?
- [ ] **Partition size**: Each 1-10 GB for manageability.
- [ ] **Unique constraints**: Must include partition key.
- [ ] **Automation**: pg_partman or cron for creation/dropping?
- [ ] **Prepared statements**: Verify runtime pruning works (EXPLAIN the prepared statement).

### Phase 6 — Configuration Review

```sql
-- Non-default settings.
SELECT name, setting, unit, source
FROM pg_settings WHERE source NOT IN ('default', 'override')
ORDER BY name;
```

#### Key Parameters

| Parameter | Check |
|---|---|
| `shared_buffers` | ~25% of system RAM |
| `effective_cache_size` | ~75% of system RAM |
| `work_mem` | Conservative (4-16 MB); work_mem * max_connections * sorts must fit |
| `maintenance_work_mem` | 256 MB-1 GB for vacuum/index builds |
| `random_page_cost` | **1.1 for SSD**, 4.0 for spinning disk |
| `effective_io_concurrency` | 200 for SSD, 2 for spinning disk |
| `checkpoint_completion_target` | 0.9 |
| `max_wal_size` | 4-16 GB for write-heavy |
| `wal_compression` | lz4 for write-heavy workloads |
| `log_min_duration_statement` | Set to catch slow queries (e.g., 200ms) |
| `idle_in_transaction_session_timeout` | Set always (30s-5min) |
| `default_statistics_target` | Raise for skewed columns |

#### Connection Pooling

- [ ] Using PgBouncer, PgCat, or Supavisor?
- [ ] Pool mode: transaction (recommended)?
- [ ] Pool size matches actual concurrency, not max_connections?

### Phase 7 — Vacuum & Maintenance Review

```sql
-- Tables needing vacuum attention.
SELECT schemaname, relname, n_live_tup, n_dead_tup,
       round(n_dead_tup::numeric / GREATEST(n_live_tup, 1), 4) AS dead_ratio,
       last_autovacuum, last_autoanalyze
FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 20;

-- XID age per table.
SELECT c.oid::regclass, age(c.relfrozenxid) AS xid_age,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS size
FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE relkind IN ('r','t','m') AND n.nspname NOT IN ('pg_toast')
ORDER BY age(c.relfrozenxid) DESC LIMIT 20;

-- Replication slot health.
SELECT slot_name, active,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS slot_lag
FROM pg_replication_slots;
```

#### Checklist

- [ ] **Autovacuum running**: Not disabled globally or per-table?
- [ ] **Large table tuning**: `autovacuum_vacuum_scale_factor` = 0.01-0.02 for
      tables >10M rows? (Default 0.2 means 20% dead before cleanup.)
- [ ] **XID wraparound**: No tables approaching `autovacuum_freeze_max_age`?
      Alert at age > 500M.
- [ ] **Inactive replication slots**: None with `active = false` retaining WAL?
      `max_slot_wal_keep_size` set?
- [ ] **idle_in_transaction_session_timeout**: Set to prevent vacuum blockage?

### Phase 8 — Migration Safety Review

Consult the lock-level reference in `references/postgres-knowledge-base.md` for
the complete mapping of ALTER TABLE operations to lock levels.

#### Critical Rules

1. **Always set `lock_timeout`** (1-5s) before any DDL. Retry with backoff.
2. **CREATE INDEX CONCURRENTLY** — never `CREATE INDEX` on production tables.
   Check for invalid indexes after failures.
3. **ADD COLUMN with DEFAULT** — instant on v11+ for non-volatile defaults only.
   Volatile defaults (e.g., `random()`) trigger a full table rewrite.
4. **NOT NULL addition** — use the safe pattern:
   ```sql
   ALTER TABLE t ADD CONSTRAINT chk CHECK (col IS NOT NULL) NOT VALID;
   ALTER TABLE t VALIDATE CONSTRAINT chk;  -- SHARE UPDATE EXCLUSIVE only
   ALTER TABLE t ALTER COLUMN col SET NOT NULL;  -- v12+ skips scan
   ALTER TABLE t DROP CONSTRAINT chk;
   ```
5. **Foreign key addition** — locks BOTH referencing AND referenced table.
   Use `NOT VALID` then `VALIDATE CONSTRAINT` separately.
6. **Column type changes** — `int` to `bigint` rewrites the table. Safe casts:
   `varchar(N)` → `varchar(M)` (M>N), `varchar` ↔ `text`, increasing precision.
7. **Batch backfills** — small batches (1000-10000 rows) with commits between.
   Never single-transaction UPDATE of millions of rows.
8. **Enum ADD VALUE** — pre-v12: cannot run in transaction. v12+: can, but value
   not usable until commit.

### Phase 9 — Security Spot-Check

```sql
-- Superuser roles (should be minimal).
SELECT rolname, rolsuper FROM pg_roles
WHERE rolsuper AND rolname NOT LIKE 'pg_%';

-- SECURITY DEFINER functions (must set search_path).
SELECT proname, prosecdef,
       pg_get_functiondef(oid) AS definition
FROM pg_proc
WHERE pronamespace = 'public'::regnamespace AND prosecdef;

-- RLS status on tables.
SELECT relname, relrowsecurity, relforcerowsecurity
FROM pg_class WHERE relkind = 'r' AND relnamespace = 'public'::regnamespace;
```

#### Checklist

- [ ] **Least privilege**: Application role is NOT superuser, NOT table owner.
- [ ] **RLS**: If used — `FORCE ROW LEVEL SECURITY` enabled? Policies have
      both USING and WITH CHECK? Functions in policies are LEAKPROOF?
      Views use `security_invoker = true` (v15+)?
- [ ] **SECURITY DEFINER**: Every such function sets `search_path`?
      (CVE-2018-1058 search path injection)
- [ ] **Authentication**: `scram-sha-256` (not `md5` or `trust`)?
- [ ] **SSL**: `hostssl` in pg_hba.conf? Client `sslmode=verify-full`?
- [ ] **SQL injection**: Parameterized queries everywhere? `format(%I, %L)` in PL/pgSQL?

## Output Format

```markdown
## PostgreSQL Review: [database name]

### Baseline Metrics

| Metric | Value |
|--------|-------|
| PostgreSQL Version | X.Y |
| DB size | X GB |
| Largest table | schema.table (X GB, ~N rows) |
| Cache hit ratio | 99.XX% |
| XID age | N (X% to wraparound) |
| Active connections | N / max_connections |

### Schema Findings

| Severity | Table.Column | Issue | Recommendation |
|----------|-------------|-------|----------------|
| CRITICAL | orders.user_id | FK column not indexed | CREATE INDEX CONCURRENTLY |
| WARN | users.created | timestamp instead of timestamptz | Use timestamptz |

### Query Plan Analysis

| Query | Location | Plan | Issue | Fix |
|-------|----------|------|-------|-----|
| list_orders | query.rs:133 | Seq Scan (cost=0..28450) | Missing index | Composite index |

### Index Recommendations

| Action | Index | Rationale | Evidence |
|--------|-------|-----------|----------|
| ADD | idx_orders_status ON orders(status) WHERE status != 'archived' | Covers list_orders | Seq Scan → Index Scan |
| DROP | idx_legacy_foo | 0 scans, 45 MB | pg_stat_user_indexes |

### Configuration Recommendations

| Parameter | Current | Proposed | Rationale |
|-----------|---------|----------|-----------|
| random_page_cost | 4.0 | 1.1 | SSD storage |
| work_mem | 4MB | 16MB | Sorts spilling to disk |

### Migration Safety

| Migration | Risk | Issue | Safe Alternative |
|-----------|------|-------|-----------------|
| add_not_null.sql | HIGH | Direct SET NOT NULL | CHECK NOT VALID + VALIDATE pattern |

### Vacuum & Maintenance

| Table | Dead Tuples | Dead % | Last Vacuum | Action |
|-------|-------------|--------|-------------|--------|
| events | 2.4M | 12% | 3 days ago | Tune autovacuum_vacuum_scale_factor |

### Summary

- **Critical**: N issues requiring immediate action
- **Warnings**: N issues to address soon
- **Info**: N observations, no action needed
```

## Anti-Patterns to Flag

1. **Guessing without measuring**: Never recommend an index without EXPLAIN
   ANALYZE evidence.
2. **Over-indexing**: Each index costs write performance and WAL volume.
3. **Missing FK indexes**: The #1 most common PostgreSQL performance mistake.
   Causes sequential scans AND deadlocks.
4. **`timestamp` instead of `timestamptz`**: Timezone-naive timestamps cause
   subtle bugs.
5. **`serial` for new tables**: Prefer `bigint GENERATED ALWAYS AS IDENTITY`.
6. **OFFSET pagination**: Use keyset pagination on large tables.
7. **Disabling autovacuum**: Almost never correct. Tune it instead.
8. **Default autovacuum settings on large tables**: 20% dead tuple threshold
   means a 1TB table needs 200GB dead rows before cleanup.
9. **DDL without lock_timeout**: A single slow query turns a 1-second DDL
   into minutes of total downtime via lock queue cascade.
10. **`idle in transaction` without timeout**: Holds snapshots, blocks vacuum,
    causes cascading bloat spiral.
11. **`SELECT *`**: Prevents index-only scans, wastes bandwidth.
12. **CREATE INDEX without CONCURRENTLY**: Blocks all writes.
13. **IF NOT EXISTS with CONCURRENTLY**: Masks invalid indexes.
14. **Direct ALTER COLUMN TYPE on large tables**: Full rewrite under ACCESS
    EXCLUSIVE. Use shadow column + backfill pattern instead.

## Related Skills

- `/performance-analyzer` — Profile application code around DB operations
- `/test-strategy` — Choose test approach for DB layer
- `/security-reviewer` — Audit SQL injection risks
