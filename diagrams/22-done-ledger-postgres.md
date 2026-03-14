# Done-Ledger PostgreSQL Backend

The `gossip-done-ledger-postgres` crate implements the [`DoneLedger`] trait
against PostgreSQL. It records which `(tenant, policy, object-version)` tuples
have been scanned, what status they reached, and which pipeline run produced the
result. The done-ledger is the single source of truth for "has this item been
scanned?" queries that let workers skip already-processed items.

The backend uses a single synchronous `postgres::Client` behind
`Arc<Mutex<_>>`, explicit transactions for every write, and a single-statement
bulk `INSERT ... SELECT * FROM unnest() ON CONFLICT` upsert that avoids
per-row round-trips and sidesteps PostgreSQL's 65,535 bind-parameter limit.

The central correctness property is **lattice-monotonic merge**: both the
Rust-side batch preprocessing and the SQL `ON CONFLICT DO UPDATE` clause
implement the same merge rules, ensuring that the durable row for a given key
converges to the same state regardless of submission order or replay count.

This document covers five systems:

1. **Backend architecture** -- struct design, constructors, trait implementation,
   and concurrency model.
2. **Batch upsert pipeline** -- validation, deduplication, column transposition,
   and SQL execution.
3. **Provenance winner-selection** -- the three-way tie-break that determines
   which run's metadata survives a merge.
4. **SQL schema and indexes** -- table structure, CHECK constraints, and index
   design.
5. **Error hierarchy** -- error classification by failure category and recovery
   path.

> **Notation.** All diagrams use the B5 Persistence color palette (purple theme:
> fill `#8B5CF6`, light fill `#EDE9FE`, stroke `#5B21B6`). Identity types from
> B1 use blue (`#3B82F6` / `#DBEAFE` / `#1E40AF`). Error paths use red
> (`#EF4444` / `#FEE2E2` / `#991B1B`). Resolved/success states use green
> (`#22C55E` / `#DCFCE7` / `#166534`). Shared infrastructure (gossip-pg-common)
> uses grey (`#6B7280` / `#F3F4F6` / `#374151`).

---

## 1. Backend Architecture

`DoneLedgerPg` wraps a `postgres::Client` in `Arc<Mutex<_>>`, making the
struct cheaply cloneable and `Send + Sync`. The mutex serialises all database
access through a single connection -- concurrent `batch_get` / `batch_upsert`
calls block on the mutex, so throughput is limited to one operation at a time.
Callers needing connection-level parallelism should create multiple instances
or front them with a connection pool.

Every `batch_upsert` executes inside an explicit transaction. The
`ReadyCommitHandle` is only constructed after `tx.commit()` succeeds, so the
receipt returned to the caller is durable-before-return -- there is no async
lag between "receipt handed out" and "data on disk."

```mermaid
%% Diagram: done-ledger-pg-architecture
graph TD
    subgraph traits ["DoneLedger trait (gossip-contracts)"]
        DL["DoneLedger<br/>batch_get() → Vec&lt;Option&lt;Record&gt;&gt;<br/>batch_upsert() → CommitHandle"]
    end

    subgraph backend ["DoneLedgerPg (gossip-done-ledger-postgres)"]
        struct["DoneLedgerPg<br/>client: Arc&lt;Mutex&lt;Client&gt;&gt;"]

        subgraph constructors ["Constructors"]
            from_client["from_client(Client)<br/>Production: caller controls TLS"]
            connect["connect(url)<br/>test-utils: NoTls"]
            connect_migrate["connect_and_migrate(url)<br/>test-utils: NoTls + migrations"]
        end

        apply_mig["apply_migrations()<br/>Idempotent, advisory-lock safe"]
        lock["lock_client()<br/>→ MutexGuard&lt;Client&gt;<br/>Poisoning = terminal"]
    end

    subgraph shared ["gossip-pg-common"]
        mig_runner["apply_all_migrations()<br/>Advisory lock + checksum"]
        types_mod["u64 ↔ BIGINT conversion<br/>BYTEA decode helpers"]
    end

    subgraph commit ["Commit protocol"]
        tx["client.transaction()"]
        stmt["tx.prepare(UPSERT_SQL)"]
        exec["tx.execute(&stmt, &columns)"]
        commit_tx["tx.commit()"]
        receipt["ReadyCommitHandle::ok(receipt)<br/>Durable-before-return"]
    end

    DL -->|"impl"| struct
    struct --> lock
    struct --> constructors
    apply_mig --> mig_runner
    lock --> tx
    tx --> stmt
    stmt --> exec
    exec --> commit_tx
    commit_tx --> receipt

    style DL fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style struct fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style from_client fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style connect fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style connect_migrate fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style apply_mig fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style lock fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style mig_runner fill:#F3F4F6,stroke:#374151,color:#374151
    style types_mod fill:#F3F4F6,stroke:#374151,color:#374151
    style tx fill:#DCFCE7,stroke:#166534,color:#166534
    style stmt fill:#DCFCE7,stroke:#166534,color:#166534
    style exec fill:#DCFCE7,stroke:#166534,color:#166534
    style commit_tx fill:#DCFCE7,stroke:#166534,color:#166534
    style receipt fill:#DCFCE7,stroke:#166534,color:#166534
```

### Constructor summary

| Constructor | TLS | Migrations | Feature gate | Use case |
|:---|:---|:---|:---|:---|
| `from_client(Client)` | Caller-chosen | No | *(always)* | Production (TLS, pooling) |
| `connect(url)` | `NoTls` | No | `test-utils` | Quick local / test setup |
| `connect_and_migrate(url)` | `NoTls` | Yes | `test-utils` | Local dev with auto-schema |

After `from_client`, call `apply_migrations()` to run schema migrations if
needed. The advisory-lock protocol makes this safe for concurrent startup.

### Mutex poisoning

Poisoning is treated as terminal because the connection's internal state
(prepared statements, transaction nesting) is indeterminate after a panic
during SQL execution. Attempting to reuse a potentially half-committed
connection risks silent data corruption.

---

## 2. Batch Upsert Pipeline

The `batch_upsert` method is the write path. It validates, deduplicates,
transposes, and executes records in a single SQL round-trip per call.

```mermaid
%% Diagram: batch-upsert-pipeline
flowchart TB
    input["&[DoneLedgerRecord]<br/>(up to 10,000 records)"]

    input --> size_check{"len > RECOMMENDED_MAX_BATCH_SIZE<br/>(10,000)?"}
    size_check -->|"yes"| err_batch["BatchTooLarge"]
    size_check -->|"no"| empty_check{"empty?"}
    empty_check -->|"yes"| receipt_zero["ReadyCommitHandle::ok(0, 0, 0)"]

    empty_check -->|"no"| dedupe["dedupe_and_validate()"]

    subgraph dedupe_box ["Deduplicate and validate"]
        direction TB
        validate["For each record:<br/>1. record.validate() — cross-field invariants<br/>2. started_at ≤ finished_at — provenance ordering"]
        validate --> merge_dup{"Duplicate key?"}
        merge_dup -->|"first seen"| insert_order["Insert into HashMap + order Vec"]
        merge_dup -->|"duplicate"| lattice["DoneLedgerRecord::merge()<br/>Lattice merge (higher status wins)"]
        lattice --> post_validate["merged.validate()<br/>Defensive re-validation"]
    end

    dedupe --> columns["collect_columns()"]

    subgraph transpose ["Column transposition"]
        direction TB
        col_desc["Transpose N records into<br/>12 column-parallel arrays:<br/>tenant_ids: Vec&lt;Vec&lt;u8&gt;&gt;<br/>policy_hashes: Vec&lt;Vec&lt;u8&gt;&gt;<br/>ovid_hashes: Vec&lt;Vec&lt;u8&gt;&gt;<br/>statuses: Vec&lt;i16&gt;<br/>bytes_scanned: Vec&lt;i64&gt;<br/>findings_counts: Vec&lt;i32&gt;<br/>run_ids: Vec&lt;i64&gt;<br/>shard_ids: Vec&lt;i64&gt;<br/>fence_epochs: Vec&lt;i64&gt;<br/>started_ats: Vec&lt;i64&gt;<br/>finished_ats: Vec&lt;i64&gt;<br/>error_codes: Vec&lt;Option&lt;String&gt;&gt;"]
    end

    columns --> sql_exec["Single SQL execution:<br/>INSERT INTO ... SELECT * FROM unnest(<br/>  $1::bytea[], ..., $12::text[]<br/>) ON CONFLICT ... DO UPDATE"]
    sql_exec --> commit["tx.commit()"]
    commit --> receipt["ReadyCommitHandle::ok(build_receipt(&merged))"]

    style input fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style size_check fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style err_batch fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style empty_check fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style receipt_zero fill:#DCFCE7,stroke:#166534,color:#166534
    style validate fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style merge_dup fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style insert_order fill:#DCFCE7,stroke:#166534,color:#166534
    style lattice fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style post_validate fill:#DBEAFE,stroke:#1E40AF,color:#1E40AF
    style col_desc fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style sql_exec fill:#DCFCE7,stroke:#166534,color:#166534
    style commit fill:#DCFCE7,stroke:#166534,color:#166534
    style receipt fill:#DCFCE7,stroke:#166534,color:#166534
```

### Why `unnest()` instead of multi-row `VALUES`

The PostgreSQL bind-parameter limit is 65,535. With 12 columns per row, a
dynamic multi-row `VALUES` clause hits the limit at ~5,461 rows (12 x 5,461 =
65,532). The `unnest()` approach uses exactly 12 parameters regardless of batch
size, and the server expands the arrays into rows internally. This avoids both
the parameter limit and the N round-trips of a per-row INSERT loop.

### Column encoding strategies

| Column class | Strategy | Columns | Rationale |
|:---|:---|:---|:---|
| Identity (equality-only) | Bit-pattern (`as i64`) | `run_id`, `shard_id` | SQL uses only `=` and `GROUP BY` -- signed ordering is irrelevant |
| Ordered (sortable) | Checked non-negative | `bytes_scanned`, `fence_epoch`, `started_at`, `finished_at` | SQL `ORDER BY`, `GREATEST`, and range-scan indexes depend on signed integer ordering matching logical counter ordering |
| Status rank | Direct cast (`rank as i16`) | `status` | SMALLINT holds the 1-11 rank range |
| Findings count | Checked (`u32 → i32`) | `findings_count` | INTEGER handles valid count range |
| Error code | Optional string | `error_code` | Nullable TEXT, max 128 bytes |

Values exceeding `i64::MAX` in ordered columns are rejected with
`Conversion { record_index }` rather than silently misordered.

### Receipt computation

The receipt is computed from the *merged* record set, not the original input.
Duplicates within a batch do not inflate the receipt counts.

| Receipt field | Computation |
|:---|:---|
| `record_count` | Number of distinct keys after dedup |
| `scanned_count` | Records with `status.is_scanned()` (ScannedClean or ScannedWithFindings) |
| `findings_count` | Saturating sum of `findings_count` across all records |

---

## 3. Provenance Winner-Selection: Three-Way Tie-Break

When two `DoneLedgerRecord` values share the same primary key `(tenant_id,
policy_hash, ovid_hash)`, the merge must decide which provenance to keep. The
decision tree below is implemented identically in Rust
(`DoneLedgerRecord::merge`) and in SQL (`UPSERT_SQL`).

The done-ledger merge differs from the observation merge (diagram 21) in two
key ways: (1) status uses a lattice join (`GREATEST`) rather than a simple
comparison, and (2) `findings_count` has status-dependent merge logic.

```mermaid
%% Diagram: provenance-winner-selection
flowchart TB
    start(["Two DoneLedgerRecords<br/>same (tenant_id, policy_hash, ovid_hash)"])

    start --> status_merge["Status = GREATEST(existing.rank, incoming.rank)<br/>Lattice join: higher rank = more terminal state"]

    status_merge --> bs_merge["bytes_scanned = GREATEST(existing, incoming)<br/>Non-regressing: larger scan always wins"]

    bs_merge --> fc_merge{"Merged status?"}
    fc_merge -->|"ScannedClean (10)"| fc_zero["findings_count = 0<br/>Clean scan resets count"]
    fc_merge -->|"ScannedWithFindings (11)"| fc_floor["findings_count = GREATEST(<br/>existing, incoming, 1)<br/>Floor of 1 guarantees<br/>ScannedWithFindings ≥ 1"]
    fc_merge -->|"Other (1, 2, 3)"| fc_max["findings_count = GREATEST(<br/>existing, incoming)<br/>Best-effort preserves<br/>pre-failure count"]

    fc_zero --> prov_cmp
    fc_floor --> prov_cmp
    fc_max --> prov_cmp

    prov_cmp{"Provenance winner?<br/>(three-way tie-break)"}
    prov_cmp -->|"1. incoming.status > existing.status"| inc["Winner = incoming"]
    prov_cmp -->|"2. equal status,<br/>incoming.finished_at > existing"| inc
    prov_cmp -->|"3. equal status + finished_at,<br/>incoming.started_at > existing"| inc
    prov_cmp -->|"otherwise"| ext["Winner = existing"]

    inc --> assemble["Provenance fields from winner:<br/>run_id, shard_id, fence_epoch,<br/>started_at, finished_at<br/>(all 5 from same record)"]
    ext --> assemble

    assemble --> err_code{"Merged status is scanned?<br/>(rank 10 or 11)"}
    err_code -->|"yes"| ec_null["error_code = NULL<br/>Scanned rows have no error"]
    err_code -->|"no"| ec_coalesce["error_code = COALESCE(<br/>winner.error_code,<br/>loser.error_code)<br/>Prefer winner's code"]

    ec_null --> result["Merged DoneLedgerRecord"]
    ec_coalesce --> result

    style start fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style status_merge fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style bs_merge fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style fc_merge fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style fc_zero fill:#DCFCE7,stroke:#166534,color:#166534
    style fc_floor fill:#DCFCE7,stroke:#166534,color:#166534
    style fc_max fill:#DCFCE7,stroke:#166534,color:#166534
    style prov_cmp fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style inc fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style ext fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style assemble fill:#DCFCE7,stroke:#166534,color:#166534
    style err_code fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style ec_null fill:#DCFCE7,stroke:#166534,color:#166534
    style ec_coalesce fill:#DCFCE7,stroke:#166534,color:#166534
    style result fill:#DCFCE7,stroke:#166534,color:#166534
```

### Merge-rule invariants

These invariants must hold in both the Rust implementation and the SQL
`CASE` expressions. Divergence constitutes a correctness bug verified by
property tests in `merge_parity_proptest.rs`.

| # | Invariant | Rust | SQL |
|:---|:---|:---|:---|
| 1 | **Status**: lattice join via `GREATEST` | `DoneLedgerStatus::merge()` returns `max(rank)` | `GREATEST(EXCLUDED.status, done_ledger_entries.status)` |
| 2 | **bytes_scanned**: non-regressing | `.max()` | `GREATEST(EXCLUDED.bytes_scanned, ...)` |
| 3 | **findings_count**: status-dependent | Match on merged status: `ScannedClean → 0`, `ScannedWithFindings → max(existing, incoming, 1)`, other → `max` | 3-branch `CASE` on merged status values `10`, `11`, else |
| 4 | **Provenance winner**: `status > finished_at > started_at` | Three-condition boolean | Repeated CASE predicate across 6 columns (`run_id`, `shard_id`, `fence_epoch`, `started_at`, `finished_at`, `error_code`) |
| 5 | **Provenance fields**: all from same winner | Single `winner` binding | All 6 CASE arms use the identical 3-part predicate |
| 6 | **error_code**: cleared for scanned status | `None` when merged status is scanned | `CASE WHEN ... IN (10, 11) THEN NULL` |

### Why the SQL repeats the CASE predicate 6 times

PostgreSQL's `ON CONFLICT DO UPDATE SET` does not support CTEs or local
variables. Each column assignment requires its own `CASE` expression. All 6
CASE arms must use the identical three-part predicate to ensure every
provenance field is sourced from the same winner. Edits to one branch must be
mirrored in all others.

### Why provenance is never mixed

`fence_epoch` is not independently max-tracked. In the coordination layer,
`fence_epoch` is monotonic per shard; in the done-ledger it is provenance
metadata that records _which_ epoch produced the observation. Independently
max-tracking `fence_epoch` would produce a record whose epoch belongs to a
different run/shard than the one stored.

---

## 4. SQL Schema and Indexes

The done-ledger schema enforces the domain invariants from
[`DoneLedgerRecord`](19-persistence-contracts.md) at the SQL level through CHECK
constraints and a composite primary key.

```mermaid
%% Diagram: done-ledger-schema
erDiagram
    done_ledger_entries {
        BYTEA tenant_id PK "CHECK octet_length = 32"
        BYTEA policy_hash PK "CHECK octet_length = 32"
        BYTEA ovid_hash PK "CHECK octet_length = 32"
        SMALLINT status "CHECK IN (1,2,3,10,11)"
        BIGINT bytes_scanned "CHECK >= 0"
        INTEGER findings_count "CHECK >= 0"
        BIGINT fence_epoch "CHECK >= 0"
        BIGINT started_at "CHECK >= 0"
        BIGINT finished_at "CHECK >= started_at"
        BIGINT run_id "bit-pattern: equality only"
        BIGINT shard_id "bit-pattern: equality only"
        TEXT error_code "NULL or 1-128 bytes"
    }
```

### CHECK constraints

The schema enforces three categories of constraints:

| Constraint | SQL | Domain invariant |
|:---|:---|:---|
| **Byte-length identity** | `octet_length(tenant_id) = 32` (x3) | All identity fields are fixed-size 32-byte BLAKE3 hashes |
| **Status range** | `status IN (1, 2, 3, 10, 11)` | Only known `DoneLedgerStatus` rank values are stored |
| **Non-negative ordered fields** | `bytes_scanned >= 0`, `fence_epoch >= 0`, `started_at >= 0` | SQL signed ordering matches logical counter ordering |
| **Temporal ordering** | `finished_at >= started_at` | Provenance time range is well-formed |
| **Error code size** | `error_code IS NULL OR octet_length(...) BETWEEN 1 AND 128` | Matches `MAX_DONE_LEDGER_ERROR_CODE_SIZE` |
| **Status-shape** | 3-branch CHECK (see below) | Cross-field consistency between status, findings_count, and error_code |

The status-shape constraint is the most important:

```
(status = 10 AND findings_count = 0 AND error_code IS NULL)       -- ScannedClean
OR (status = 11 AND findings_count > 0 AND error_code IS NULL)    -- ScannedWithFindings
OR (status IN (1, 2, 3) AND error_code IS NOT NULL)               -- Failure/Skip
```

This mirrors the cross-field validation in `DoneLedgerRecord::try_new` and
`validate()`. A row that passes the Rust-side validation but violates the SQL
constraint would indicate a divergence between the domain model and the schema.

### Index design

```mermaid
%% Diagram: done-ledger-indexes
graph LR
    subgraph pk ["Primary Key"]
        pk_cols["(tenant_id, policy_hash, ovid_hash)<br/>Composite PK = lookup by done-ledger key"]
    end

    subgraph retention_idx ["Retention / Scan-History Index"]
        ret_cols["(tenant_id, policy_hash,<br/>finished_at DESC, ovid_hash)<br/>Covering index for tenant+policy scans"]
        ret_use["Use cases:<br/>• Enumerate scanned items per policy<br/>• Retention age queries<br/>• Index-only scan (trailing ovid_hash<br/>  covers the PK lookup)"]
    end

    subgraph debug_idx ["Provenance Debug Index"]
        debug_cols["(run_id, shard_id,<br/>tenant_id, policy_hash, ovid_hash)<br/>Covering index for provenance lookups"]
        debug_use["Use cases:<br/>• Which rows did run X + shard Y produce?<br/>• Post-incident investigation<br/>• Operational debugging"]
    end

    style pk_cols fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style ret_cols fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style ret_use fill:#F3F4F6,stroke:#374151,color:#374151
    style debug_cols fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style debug_use fill:#F3F4F6,stroke:#374151,color:#374151
```

The retention index uses `finished_at DESC` because the most common query
pattern is "newest completions first." The trailing `ovid_hash` column makes
the index _covering_ for the primary key, so retention scans operate as
index-only scans without hitting the heap.

The provenance index enables operational debugging: "which rows did a specific
run + shard produce?" This is essential for post-incident investigation when a
pipeline run produced incorrect results.

### u64 ↔ BIGINT encoding

Done-ledger columns use two encoding strategies depending on how SQL accesses
them:

```mermaid
%% Diagram: bigint-encoding-strategies
flowchart LR
    subgraph bitpattern ["Bit-Pattern Storage"]
        bp_rule["u64 value → reinterpret as i64<br/>No range check"]
        bp_cols["Columns: run_id, shard_id"]
        bp_ops["SQL operations: =, GROUP BY<br/>Ordering is never used"]
        bp_round["Roundtrip: u64 → i64 → u64<br/>Lossless for all u64 values"]
    end

    subgraph ordered ["Checked Non-Negative Storage"]
        ord_rule["u64 value → reject if > i64::MAX<br/>Store as non-negative BIGINT"]
        ord_cols["Columns: bytes_scanned,<br/>fence_epoch, started_at,<br/>finished_at"]
        ord_ops["SQL operations: >, >=, GREATEST,<br/>ORDER BY, index range scans"]
        ord_guard["Guard: values above i64::MAX<br/>would invert SQL ordering →<br/>rejected at encode time"]
    end

    style bp_rule fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style bp_cols fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style bp_ops fill:#F3F4F6,stroke:#374151,color:#374151
    style bp_round fill:#DCFCE7,stroke:#166534,color:#166534
    style ord_rule fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style ord_cols fill:#8B5CF6,stroke:#5B21B6,color:#FFF
    style ord_ops fill:#F3F4F6,stroke:#374151,color:#374151
    style ord_guard fill:#FEE2E2,stroke:#991B1B,color:#991B1B
```

---

## 5. Error Hierarchy

The error types are organized into two enums: `DoneLedgerPgError` (the
`DoneLedger::Error` associated type) and `DoneLedgerPgConversionError` (Rust ↔
PostgreSQL type-boundary failures). Errors fall into four categories:
infrastructure, input validation, merge logic, and decode-time.

```mermaid
%% Diagram: done-ledger-error-hierarchy
flowchart TB
    subgraph top ["DoneLedgerPgError (DoneLedger::Error)"]
        direction TB

        subgraph infra ["Infrastructure"]
            pg["Postgres(postgres::Error)<br/>Connection/SQL failure"]
            mig["Migration(PgMigrationError)<br/>Schema migration failure"]
            mutex["MutexPoisoned<br/>Prior panic poisoned mutex"]
        end

        subgraph input_val ["Input Validation"]
            batch["BatchTooLarge { operation, len, max }<br/>Batch exceeds 10,000 records"]
            invalid["InvalidRecord { index, source }<br/>Record failed validate()"]
            prov_inv["ProvenanceInvalid { index,<br/>started_at, finished_at }<br/>Temporal ordering violated"]
        end

        subgraph merge_err ["Merge Logic"]
            merged["InvalidMergedRecord { source }<br/>Duplicate-key fold produced<br/>invalid composite record"]
        end

        subgraph decode ["Decode-Time"]
            conv["Conversion { record_index, source }<br/>Rust ↔ SQL type-boundary failure"]
            persisted["PersistedRecordInvalid { context, source }<br/>Stored row failed decode validation"]
        end
    end

    subgraph conv_err ["DoneLedgerPgConversionError"]
        u64_conv["U64Conversion(PgU64ConversionError)<br/>BIGINT range violation"]
        byte_dec["ByteDecode(PgByteDecodeError)<br/>BYTEA length mismatch"]
        status_rank["UnknownStatusRank { rank: i16 }<br/>Stored rank has no DoneLedgerStatus"]
        fc_range["FindingsCountOutOfRange { value: i64 }<br/>Does not fit in u32"]
    end

    conv -->|"source"| conv_err

    style pg fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style mig fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style mutex fill:#FEE2E2,stroke:#991B1B,color:#991B1B
    style batch fill:#FFF7ED,stroke:#9A3412,color:#9A3412
    style invalid fill:#FFF7ED,stroke:#9A3412,color:#9A3412
    style prov_inv fill:#FFF7ED,stroke:#9A3412,color:#9A3412
    style merged fill:#EDE9FE,stroke:#5B21B6,color:#5B21B6
    style conv fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style persisted fill:#C4B5FD,stroke:#5B21B6,color:#5B21B6
    style u64_conv fill:#F3F4F6,stroke:#374151,color:#374151
    style byte_dec fill:#F3F4F6,stroke:#374151,color:#374151
    style status_rank fill:#F3F4F6,stroke:#374151,color:#374151
    style fc_range fill:#F3F4F6,stroke:#374151,color:#374151
```

### Error categorization

| Category | Variants | Typical cause | Recovery |
|:---|:---|:---|:---|
| **Infrastructure** | `Postgres`, `Migration`, `MutexPoisoned` | Network failure, schema drift, prior panic | Retry (Postgres), fix schema (Migration), restart (MutexPoisoned) |
| **Input validation** | `BatchTooLarge`, `InvalidRecord`, `ProvenanceInvalid` | Caller-supplied invalid data | Fix upstream: smaller batches, valid records |
| **Merge logic** | `InvalidMergedRecord` | Duplicate-key fold produced a record violating domain invariants | Likely a bug in merge logic |
| **Decode-time** | `Conversion`, `PersistedRecordInvalid` | Schema drift or data corruption in stored rows | Investigate stored data; may require migration |

### Migration system

The migration subsystem delegates to `gossip-pg-common` and uses:

| Component | Value | Purpose |
|:---|:---|:---|
| Advisory lock key | `0x4753444c50474d31` ("GSDLPGM1") | Serialises concurrent migration attempts |
| History table | `done_ledger_schema_migrations` | Records applied versions with BLAKE3 checksums |
| Checksum algorithm | BLAKE3 | Detects SQL text tampering post-application |

Migrations are append-only: new migrations are added to the end of the
`MIGRATIONS` slice. Existing migrations are immutable -- the checksum
test in `migrations.rs` pins each migration's SQL text hash. If the SQL
changes, the test fails, preventing silent schema drift.

---

## Batch-Get: Positional Alignment

The `batch_get` method preserves the caller's requested order. PostgreSQL
returns matching rows in arbitrary order, so the Rust caller restores
positional alignment:

1. Execute `SELECT ... WHERE ovid_hash = ANY($3::bytea[])` in a single
   round-trip.
2. Index results into a `HashMap<OvidHash, DoneLedgerRecord>`.
3. Project back onto the input `ovid_hashes` slice, yielding `None` for
   missing keys and duplicated results for duplicated inputs.

This guarantees that `result[i]` corresponds to `ovid_hashes[i]`, enabling
callers to zip results with their input without sorting.

### Row decoding

Each row passes through three validation layers:

1. **Type-level conversion**: byte length checks, `u64` range mapping, status
   rank resolution.
2. **Construction-time invariants**: `DoneLedgerRecord::try_new` enforces
   cross-field rules (e.g., `ScannedClean` requires `findings_count == 0`).
3. **Post-construction validation**: `DoneLedgerRecord::validate()` catches any
   invariant the constructor might not enforce.

Any failure at any layer produces `PersistedRecordInvalid` or `Conversion`,
indicating data corruption or schema drift.

---

## Cross-References

- [Persistence Contracts](19-persistence-contracts.md) -- the `DoneLedger`
  trait, `DoneLedgerRecord`, `DoneLedgerStatus` lattice, `DoneLedgerKey`,
  `DoneLedgerProvenance`, and `OVID` hashing that this backend implements
- [Findings PostgreSQL Backend](21-findings-postgres-dedup.md) -- the sibling
  PostgreSQL backend for findings, using similar `ON CONFLICT` patterns with
  different merge semantics
- [PageCommit Typestate Machine](08-pagecommit-typestate.md) -- the compile-time
  ordering guarantee that findings are durable before done-ledger writes
- [End-to-End Scan Flow](04-end-to-end-scan-flow.md) -- where done-ledger
  lookups and updates occur in the scan pipeline

## Source Code References

| File | Purpose |
|:---|:---|
| `crates/gossip-done-ledger-postgres/src/backend.rs` | `DoneLedgerPg` struct, `DoneLedger` trait impl, `dedupe_and_validate`, `collect_columns`, `decode_row`, `build_receipt` |
| `crates/gossip-done-ledger-postgres/src/schema.rs` | SQL constants (`BATCH_GET_SQL`, `UPSERT_SQL`), table/index/lock-key names |
| `crates/gossip-done-ledger-postgres/src/error.rs` | `DoneLedgerPgError` (9 variants), `DoneLedgerPgConversionError` (4 variants) |
| `crates/gossip-done-ledger-postgres/src/migrations.rs` | `MIGRATIONS` slice, `apply_all_migrations`, migration config |
| `crates/gossip-done-ledger-postgres/migrations/0001_done_ledger_entries.sql` | DDL: table, CHECK constraints, 2 indexes |
| `crates/gossip-pg-common/src/migration.rs` | Shared advisory-lock migration runner, `EmbeddedMigration`, checksum protocol |
| `crates/gossip-pg-common/src/types.rs` | `u64_to_pg_bigint_bits`, `u64_to_pg_bigint_checked`, `pg_bigint_to_u64_bits`, `pg_bigint_nonnegative_to_u64`, `decode_fixed_32` |
| `crates/gossip-contracts/src/persistence/done_ledger.rs` | `DoneLedger` trait, `DoneLedgerRecord`, `DoneLedgerStatus`, `DoneLedgerKey`, `DoneLedgerProvenance`, `DoneLedgerErrorCode` |
