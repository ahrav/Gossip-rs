# PostgreSQL Knowledge Base

Detailed reference material for the postgres-review skill. Consult specific
sections as needed during review phases.

---

## 1. ALTER TABLE Lock Level Reference

Every DDL operation acquires a specific lock level. ACCESS EXCLUSIVE blocks all
reads and writes. Only operations below SHARE level allow concurrent writes.

| Operation | Lock Level | Blocks Reads? | Blocks Writes? | Table Rewrite? |
|---|---|---|---|---|
| ADD COLUMN (no default) | ACCESS EXCLUSIVE | Yes | Yes | No |
| ADD COLUMN (non-volatile default, v11+) | ACCESS EXCLUSIVE | Yes (brief) | Yes (brief) | No |
| ADD COLUMN (volatile default) | ACCESS EXCLUSIVE | Yes | Yes | **Yes** |
| ADD COLUMN (stored generated) | ACCESS EXCLUSIVE | Yes | Yes | **Yes** |
| DROP COLUMN | ACCESS EXCLUSIVE | Yes (brief) | Yes (brief) | No (logical only) |
| ALTER COLUMN SET DATA TYPE | ACCESS EXCLUSIVE | Yes | Yes | **Usually yes** |
| ALTER COLUMN SET NOT NULL | ACCESS EXCLUSIVE | Yes | Yes | No (but scans table) |
| ADD CHECK CONSTRAINT | ACCESS EXCLUSIVE | Yes | Yes | No |
| ADD CHECK NOT VALID | ACCESS EXCLUSIVE | Yes (brief) | Yes (brief) | No (instant) |
| VALIDATE CONSTRAINT | SHARE UPDATE EXCLUSIVE | No | No | No |
| ADD FOREIGN KEY | SHARE ROW EXCLUSIVE | No | **Yes (both tables)** | No |
| ADD FOREIGN KEY NOT VALID | ACCESS EXCLUSIVE | Yes (brief) | Yes (brief) | No |
| SET STATISTICS | SHARE UPDATE EXCLUSIVE | No | No | No |
| SET storage params | SHARE UPDATE EXCLUSIVE | No | No | No |
| ENABLE/DISABLE TRIGGER | SHARE ROW EXCLUSIVE | No | Yes | No |
| RENAME COLUMN/TABLE | ACCESS EXCLUSIVE | Yes (brief) | Yes (brief) | No |

### Safe vs Unsafe Type Casts

**Safe casts (no table rewrite):**
- `varchar(N)` → `varchar(M)` where M > N (v9.2+)
- `varchar` ↔ `text`
- `numeric(P,S)` → `numeric(P2,S)` where P2 > P
- `timestamp(P)` → `timestamp(P2)` where P2 > P (increasing precision)

**Unsafe casts (full table rewrite under ACCESS EXCLUSIVE):**
- `int` → `bigint` (different binary representation)
- `varchar(100)` → `varchar(50)` (decreasing length)
- `timestamp` → `timestamptz` (conversion may occur)
- Any change with explicit `USING` clause that modifies data

---

## 2. Monitoring Queries

### 2.1 pg_stat_statements — Top Queries by Time

```sql
SELECT queryid, calls,
       total_exec_time::int AS total_ms,
       mean_exec_time::int AS mean_ms,
       rows, query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 20;
```
**Version**: 13+ (total_exec_time; earlier versions use `total_time`)
**Action**: Top 3-5 queries account for 50%+ of DB time. Optimize these first.

### 2.2 Queries with Poor Cache Hit Ratio

```sql
SELECT queryid, calls,
       shared_blks_hit, shared_blks_read,
       round(100.0 * shared_blks_hit /
             NULLIF(shared_blks_hit + shared_blks_read, 0), 2) AS cache_hit_pct,
       temp_blks_read + temp_blks_written AS temp_blks,
       query
FROM pg_stat_statements
WHERE shared_blks_hit + shared_blks_read > 100
ORDER BY shared_blks_read DESC LIMIT 20;
```
**Action**: cache_hit_pct < 95% for frequent queries = problem. temp_blks > 0 = spilling to disk.

### 2.3 Table Health — Dead Tuples and Vacuum Status

```sql
SELECT schemaname, relname,
       n_live_tup, n_dead_tup,
       round(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 2) AS dead_pct,
       last_vacuum, last_autovacuum,
       last_analyze, last_autoanalyze
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC;
```
**Action**: dead_pct > 10% is concerning. last_autovacuum > 24h ago with high dead tuples = vacuum falling behind.

### 2.4 Sequential Scans on Large Tables

```sql
SELECT relname, seq_scan, idx_scan,
       round(100.0 * seq_scan / NULLIF(seq_scan + idx_scan, 0), 2) AS seq_pct,
       n_live_tup,
       pg_size_pretty(pg_relation_size(relid)) AS size
FROM pg_stat_user_tables
WHERE n_live_tup > 10000 AND seq_scan > 0
ORDER BY seq_scan DESC LIMIT 20;
```
**Action**: seq_pct > 50% on table with >10K rows in OLTP = missing index.

### 2.5 Unused Indexes

```sql
SELECT schemaname || '.' || relname AS table,
       indexrelname AS index,
       pg_size_pretty(pg_relation_size(i.indexrelid)) AS size,
       idx_scan
FROM pg_stat_user_indexes i
JOIN pg_index USING (indexrelid)
WHERE NOT indisunique AND NOT indisprimary AND idx_scan = 0
ORDER BY pg_relation_size(i.indexrelid) DESC;
```
**Action**: 0 scans after representative workload period = drop candidate. Verify not used by batch jobs.

### 2.6 Duplicate Indexes

```sql
SELECT pg_size_pretty(sum(pg_relation_size(idx))::bigint) AS size,
       (array_agg(idx))[1] AS idx1, (array_agg(idx))[2] AS idx2
FROM (
    SELECT indexrelid::regclass AS idx,
           (indrelid::text || E'\n' || indclass::text || E'\n' ||
            indkey::text || E'\n' || coalesce(indexprs::text, '') ||
            E'\n' || coalesce(indpred::text, '')) AS key
    FROM pg_index
) sub GROUP BY key HAVING count(*) > 1
ORDER BY sum(pg_relation_size(idx)) DESC;
```

### 2.7 Foreign Keys Without Indexes

```sql
WITH fks AS (
    SELECT conname, conrelid, conkey::smallint[]
    FROM pg_constraint WHERE contype = 'f'
), indexes AS (
    SELECT indrelid, indkey::smallint[]
    FROM pg_index WHERE indpred IS NULL AND indisvalid
)
SELECT c.relname AS table_name, fk.conname AS fk_name,
       array_agg(a.attname ORDER BY array_position(fk.conkey, a.attnum)) AS columns
FROM fks fk
LEFT JOIN indexes ON fk.conrelid = indexes.indrelid
  AND fk.conkey = indexes.indkey[1:array_length(fk.conkey, 1)]
JOIN pg_class c ON fk.conrelid = c.oid
JOIN pg_attribute a ON fk.conrelid = a.attrelid AND a.attnum = ANY(fk.conkey)
WHERE indexes.indrelid IS NULL
GROUP BY c.relname, fk.conname;
```
**Action**: EVERY unindexed FK on a table with >1000 rows needs an index. Causes 150x slowdown on DELETE/UPDATE of parent table + deadlocks under concurrency.

### 2.8 Lock Tree (Recursive)

```sql
WITH RECURSIVE activity AS (
  SELECT pg_blocking_pids(pid) blocked_by, *,
    age(clock_timestamp(), xact_start)::interval(0) AS tx_age
  FROM pg_stat_activity WHERE state IS DISTINCT FROM 'idle'
), blockers AS (
  SELECT array_agg(DISTINCT c ORDER BY c) AS pids
  FROM (SELECT unnest(blocked_by) FROM activity) AS dt(c)
), tree AS (
  SELECT activity.*, 1 AS level, activity.pid AS top_blocker_pid,
    ARRAY[activity.pid] AS path
  FROM activity, blockers
  WHERE ARRAY[pid] <@ blockers.pids AND blocked_by = '{}'::int[]
  UNION ALL
  SELECT activity.*, tree.level + 1, tree.top_blocker_pid,
    path || ARRAY[activity.pid]
  FROM activity, tree
  WHERE activity.blocked_by <> '{}'::int[]
    AND tree.pid = ANY(activity.blocked_by)
    AND NOT ARRAY[activity.pid] <@ tree.path
)
SELECT pid, blocked_by,
  CASE WHEN wait_event_type = 'Lock' THEN 'waiting' ELSE state END AS state,
  tx_age,
  format('%s %s%s', lpad('[' || pid::text || ']', 9, ' '),
    repeat('.', level - 1) || CASE WHEN level > 1 THEN ' ' END,
    left(query, 200)) AS query
FROM tree ORDER BY top_blocker_pid, level, pid;
```
**Version**: 9.6+ (pg_blocking_pids)
**Action**: Any lock wait > 30s in production is concerning. Root blockers with many blocked PIDs = high-priority.

### 2.9 XID Wraparound Monitoring

```sql
WITH max_age AS (
    SELECT 2000000000 AS max_old_xid,
        setting AS freeze_max FROM pg_settings
    WHERE name = 'autovacuum_freeze_max_age'
)
SELECT datname, age(d.datfrozenxid) AS xid_age,
    round(100.0 * age(d.datfrozenxid) / m.max_old_xid, 2) AS pct_wraparound,
    round(100.0 * age(d.datfrozenxid) / m.freeze_max::bigint, 2) AS pct_emergency
FROM pg_database d, max_age m WHERE datallowconn;
```
**Action**: pct_wraparound > 50% = warning. > 75% = critical. pct_emergency > 100% = emergency autovacuum already running.

### 2.10 Per-Table XID Age

```sql
SELECT c.oid::regclass, age(c.relfrozenxid) AS xid_age,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS size
FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE relkind IN ('r','t','m') AND n.nspname NOT IN ('pg_toast')
ORDER BY age(c.relfrozenxid) DESC LIMIT 20;
```

### 2.11 Replication Lag

```sql
-- Primary side.
SELECT pid, application_name, state,
       write_lag, flush_lag, replay_lag,
       pg_wal_lsn_diff(sent_lsn, replay_lsn) AS replay_lag_bytes
FROM pg_stat_replication;

-- Slot health.
SELECT slot_name, slot_type, active,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS slot_lag
FROM pg_replication_slots;
```
**Action**: replay_lag > 1 min = HA concern. Inactive slots retaining >1GB WAL = drop or investigate.

### 2.12 Table Size Breakdown

```sql
SELECT nspname AS schema, relname AS table,
       c.reltuples::bigint AS rows,
       pg_size_pretty(pg_relation_size(c.oid)) AS data,
       pg_size_pretty(pg_indexes_size(c.oid)) AS indexes,
       pg_size_pretty(pg_total_relation_size(reltoastrelid)) AS toast,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total
FROM pg_class c
LEFT JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE relkind = 'r' AND nspname NOT IN ('pg_catalog','information_schema')
ORDER BY pg_total_relation_size(c.oid) DESC;
```

### 2.13 Checkpoint and WAL Monitoring

```sql
-- PG16 and earlier (pg_stat_bgwriter). PG17+ uses pg_stat_checkpointer.
SELECT
  CASE WHEN checkpoints_timed + checkpoints_req > 0
       THEN round(100.0 * checkpoints_req / (checkpoints_timed + checkpoints_req))
       ELSE 0 END AS checkpoints_req_pct,
  round(100.0 * buffers_backend /
        NULLIF(buffers_checkpoint + buffers_clean + buffers_backend, 0)) AS backend_write_pct
FROM pg_stat_bgwriter;
```
**Action**: checkpoints_req_pct > 10% = increase max_wal_size. backend_write_pct > 5% = tune bgwriter.

### 2.14 Vacuum Progress

```sql
SELECT p.pid, p.relid::regclass AS table_name, p.phase,
       round(100.0 * p.heap_blks_vacuumed / NULLIF(p.heap_blks_total, 0), 1) AS pct,
       p.index_vacuum_count, p.num_dead_tuples,
       age(clock_timestamp(), a.xact_start)::interval(0) AS duration
FROM pg_stat_progress_vacuum p
JOIN pg_stat_activity a USING (pid);
```
**Action**: index_vacuum_count > 1 = maintenance_work_mem too low (dead tuple buffer filled).

### 2.15 Long-Running Queries and idle_in_transaction

```sql
SELECT pid, state, wait_event_type, wait_event,
       age(clock_timestamp(), xact_start)::interval(0) AS tx_age,
       age(clock_timestamp(), query_start)::interval(0) AS query_age,
       usename, left(query, 200) AS query
FROM pg_stat_activity
WHERE state != 'idle' AND pid != pg_backend_pid()
ORDER BY CASE state WHEN 'idle in transaction' THEN 0 ELSE 1 END, xact_start;
```
**Action**: idle_in_transaction > 5 min = blocks vacuum, holds locks. Set idle_in_transaction_session_timeout.

---

## 3. Bloat Estimation

### Table Bloat (Statistical)

```sql
SELECT current_database(), schemaname, tablename,
  round((CASE WHEN otta=0 THEN 0.0
         ELSE sml.relpages::float/otta END)::numeric, 1) AS tbloat,
  CASE WHEN relpages < otta THEN 0
       ELSE bs*(sml.relpages-otta)::bigint END AS wastedbytes
FROM (
  SELECT schemaname, tablename, cc.reltuples, cc.relpages, bs,
    CEIL((cc.reltuples*((datahdr+ma-
      (CASE WHEN datahdr%ma=0 THEN ma ELSE datahdr%ma END))+nullhdr2+4))
      /(bs-20::float)) AS otta
  FROM (
    SELECT ma, bs, schemaname, tablename,
      (datawidth+(hdr+ma-(CASE WHEN hdr%ma=0 THEN ma ELSE hdr%ma END)))::numeric AS datahdr,
      (maxfracsum*(nullhdr+ma-(CASE WHEN nullhdr%ma=0 THEN ma ELSE nullhdr%ma END))) AS nullhdr2
    FROM (
      SELECT schemaname, tablename, hdr, ma, bs,
        SUM((1-null_frac)*avg_width) AS datawidth,
        MAX(null_frac) AS maxfracsum,
        hdr+(SELECT 1+count(*)/8 FROM pg_stats s2
             WHERE null_frac<>0 AND s2.schemaname=s.schemaname
             AND s2.tablename=s.tablename) AS nullhdr
      FROM pg_stats s,
        (SELECT (SELECT current_setting('block_size')::numeric) AS bs,
          CASE WHEN substring(v,12,3) IN ('8.0','8.1','8.2') THEN 27 ELSE 23 END AS hdr,
          CASE WHEN v ~ 'mingw32' THEN 8 ELSE 4 END AS ma
         FROM (SELECT version() AS v) AS foo
        ) AS constants
      GROUP BY 1,2,3,4,5
    ) AS foo
  ) AS rs
  JOIN pg_class cc ON cc.relname = rs.tablename
  JOIN pg_namespace nn ON cc.relnamespace = nn.oid
    AND nn.nspname = rs.schemaname
    AND nn.nspname <> 'information_schema'
) AS sml
WHERE sml.relpages - otta > 128
ORDER BY wastedbytes DESC;
```
**Action**: tbloat > 2.0 or wastedbytes > 1GB = investigate. For precision, use pgstattuple extension.

---

## 4. Autovacuum Tuning Reference

### Default Trigger Formula

```
dead_tuples > autovacuum_vacuum_threshold + (autovacuum_vacuum_scale_factor * reltuples)
```

Defaults: threshold=50, scale_factor=0.20

| Table Size | Dead Tuples Before Vacuum (default) | Recommended Override |
|---|---|---|
| 100K rows | 20,050 | scale_factor=0.05 |
| 1M rows | 200,050 | scale_factor=0.02, threshold=1000 |
| 10M rows | 2,000,050 | scale_factor=0.01, threshold=1000 |
| 100M rows | 20,000,050 | scale_factor=0.01, threshold=5000 |
| 1B rows | 200,000,050 | scale_factor=0.005, threshold=10000 |

### Per-Table Override

```sql
ALTER TABLE large_events SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_threshold = 1000,
    autovacuum_analyze_scale_factor = 0.005,
    autovacuum_analyze_threshold = 500
);
```

### Cost-Based Throttling

Each page access accumulates cost: hit=1, miss=2, dirty=20. Workers sleep when
accumulated cost reaches `autovacuum_vacuum_cost_limit` (default 200).

**The cost limit is shared among all autovacuum workers.** Increasing
`autovacuum_max_workers` without increasing cost_limit makes each worker slower.

Production recommendation:
- `autovacuum_vacuum_cost_delay` = 0-2ms (default 2ms; set to 0 for SSDs)
- `autovacuum_vacuum_cost_limit` = 1000-2000 (default 200)
- `autovacuum_max_workers` = 4-6 (default 3)

---

## 5. Migration Safety Patterns

### Safe NOT NULL Addition (v12+)

```sql
-- Step 1: Add NOT VALID CHECK (instant, brief ACCESS EXCLUSIVE).
SET lock_timeout = '5s';
ALTER TABLE users ADD CONSTRAINT chk_email_nn
  CHECK (email IS NOT NULL) NOT VALID;

-- Step 2: Validate (full scan, SHARE UPDATE EXCLUSIVE — no read/write block).
ALTER TABLE users VALIDATE CONSTRAINT chk_email_nn;

-- Step 3: Formal NOT NULL (instant — v12+ skips scan since validated CHECK exists).
SET lock_timeout = '5s';
ALTER TABLE users ALTER COLUMN email SET NOT NULL;

-- Step 4: Drop redundant CHECK.
SET lock_timeout = '5s';
ALTER TABLE users DROP CONSTRAINT chk_email_nn;
```

### Safe Foreign Key Addition

```sql
-- NOT VALID = brief ACCESS EXCLUSIVE, no validation scan.
SET lock_timeout = '5s';
ALTER TABLE orders ADD CONSTRAINT fk_customer
  FOREIGN KEY (customer_id) REFERENCES customers(id) NOT VALID;

-- VALIDATE = SHARE UPDATE EXCLUSIVE on orders, ROW SHARE on customers.
ALTER TABLE orders VALIDATE CONSTRAINT fk_customer;
```

### Safe Column Type Change (when rewrite required)

```sql
-- 1. Add new column.
SET lock_timeout = '5s';
ALTER TABLE t ADD COLUMN new_col bigint;

-- 2. Backfill in batches.
UPDATE t SET new_col = old_col WHERE id BETWEEN 1 AND 10000;
-- Repeat...

-- 3. Application writes to both columns.
-- 4. Swap reads to new column.
-- 5. Drop old column.
SET lock_timeout = '5s';
ALTER TABLE t DROP COLUMN old_col;
ALTER TABLE t RENAME COLUMN new_col TO old_col;
```

### Safe Table/Column Rename

```sql
BEGIN;
ALTER TABLE chainwheel RENAME TO sprocket;
CREATE VIEW chainwheel AS SELECT * FROM sprocket;
COMMIT;
-- Deploy code to use "sprocket", then drop view.
```

### CREATE INDEX CONCURRENTLY Recovery

```sql
-- After failure, check for invalid indexes:
SELECT indexrelid::regclass FROM pg_index WHERE NOT indisvalid;

-- Option 1: Drop and retry.
DROP INDEX CONCURRENTLY IF EXISTS idx_name;
CREATE INDEX CONCURRENTLY idx_name ON t(col);

-- Option 2 (v12+): REINDEX.
REINDEX INDEX CONCURRENTLY idx_name;
```

**Never use `IF NOT EXISTS` with CONCURRENTLY** — it silently succeeds when an
invalid index of that name already exists.

---

## 6. RLS Security Checklist

The 16 known footguns (source: Bytebase, CVE-2019-10130):

1. Superusers bypass RLS → use non-superuser application role
2. Table owners bypass RLS → `ALTER TABLE t FORCE ROW LEVEL SECURITY`
3. SECURITY DEFINER views bypass → use `security_invoker = true` (v15+)
4. Materialized views export bypassing RLS → restrict access to matviews
5. Connection poolers share `current_user` → use session variables (`SET app.tenant_id`)
6. Permissive policies OR-ed → one broad policy negates others
7. USING without WITH CHECK → allows unauthorized inserts
8. Non-LEAKPROOF functions disable index usage → performance collapse
9. Unique constraints leak data existence → scope uniqueness to tenant
10. CVE-2019-10130: planner statistics leaked data → upgrade PostgreSQL
11. COPY can bypass RLS in some configs → verify COPY behavior
12. Inheritance tables bypass parent RLS → RLS on each partition
13. `pg_dump` exports data bypassing RLS → restrict pg_dump role
14. `\copy` in psql runs as client → verify role
15. Triggers fire under owner privileges → audit trigger behavior
16. Missing default-deny → always create RESTRICTIVE catch-all policy

---

## 7. Configuration Quick Reference

### Memory

| Parameter | Formula | Notes |
|---|---|---|
| shared_buffers | 25% of RAM | Diminishing returns above 40% |
| effective_cache_size | 75% of RAM | Hint to planner, no memory allocated |
| work_mem | RAM / max_connections / 4 | Per-sort, per-hash operation. OOM risk if too high |
| maintenance_work_mem | 256MB-1GB | For VACUUM, CREATE INDEX. Higher = fewer index passes |
| hash_mem_multiplier | 2.0 (default) | Multiplied by work_mem for hash operations |

### Planner

| Parameter | SSD | HDD |
|---|---|---|
| random_page_cost | 1.1 | 4.0 |
| effective_io_concurrency | 200 | 2 |
| seq_page_cost | 1.0 | 1.0 |

### WAL & Checkpoints

| Parameter | Default | Write-Heavy Recommendation |
|---|---|---|
| max_wal_size | 1GB | 4-16GB |
| min_wal_size | 80MB | 1-2GB |
| checkpoint_completion_target | 0.9 | 0.9 |
| wal_compression | off | lz4 or zstd |
| wal_buffers | -1 (auto) | Usually fine |

### Timeouts

| Parameter | Recommendation | Why |
|---|---|---|
| idle_in_transaction_session_timeout | 30s-5min | Prevents vacuum blockage |
| lock_timeout | Set per DDL (1-5s) | Prevents lock queue cascade |
| statement_timeout | 30s-60s for OLTP | Prevents runaway queries |
| log_min_duration_statement | 200ms | Catches slow queries |

---

## 8. Key Sources

1. [PostgreSQL Official Documentation](https://www.postgresql.org/docs/current/) — authoritative reference
2. [GitLab Migration Safety Guide](https://docs.gitlab.com/development/database/avoiding_downtime_in_migrations/) — battle-tested patterns
3. [Sentry XID Wraparound Post-Mortem](https://blog.sentry.io/transaction-id-wraparound-in-postgres/) — production incident
4. [GoCardless Zero-Downtime Migrations](https://gocardless.com/blog/zero-downtime-postgres-migrations-the-hard-parts/) — lock queue cascade
5. [Duffel Autovacuum Outage](https://duffel.com/blog/understanding-outage-concurrency-vacuum-postgresql) — DDL + vacuum lock chain
6. [Bytebase RLS Footguns](https://www.bytebase.com/blog/postgres-row-level-security-footguns/) — 16 known bypass vectors
7. [CVE-2018-1058 Search Path Guide](https://wiki.postgresql.org/wiki/A_Guide_to_CVE-2018-1058:_Protect_Your_Search_Path) — SECURITY DEFINER risk
8. [Notion Sharding](https://www.notion.com/blog/sharding-postgres-at-notion) — application-level sharding at scale
9. [Cloudflare PostgreSQL at Scale](https://www.infoq.com/articles/cloudflare-distributed-postgres/) — 55M ops/sec architecture
10. [PostgreSQL Wiki: Lock Monitoring](https://wiki.postgresql.org/wiki/Lock_Monitoring) — canonical lock queries
