# Boundary 5 -- Persistence Architecture

> **Status: Core data types and traits implemented in `crates/gossip-contracts/src/persistence/`.**
> The Rust types below (`DoneLedger`, `FindingsSink`, `CommitHandle`,
> `CommitReceipt`, `PageCommit<S>`, and supporting record/receipt types)
> are compiled code with full test coverage. The coordination backend
> trait lives in `gossip-coordination` as `CoordinationBackend`
> (`crates/gossip-coordination/src/traits.rs`). The in-memory reference
> backend lives in `gossip-persistence-inmemory`
> (see [gossip-persistence-inmemory.md](../gossip-persistence-inmemory.md)).
> PostgreSQL done-ledger backend, schema, migrations, and conversion helpers live in
> `gossip-done-ledger-postgres`
> (`crates/gossip-done-ledger-postgres/src/`). Shared `u64 ↔ BIGINT` conversion
> types, embedded migration descriptors, migration configuration, shared runner
> functions, checksum verification, `PgMigrationError`, `MigrationOperation`,
> and the shared PostgreSQL integration-test lifecycle helpers live in
> `gossip-pg-common` (`crates/gossip-pg-common/src/`). Findings PostgreSQL backend,
> schema, migrations, type-mapping support, and Rust-side batch-folding helpers live in
> `gossip-findings-postgres`
> (`crates/gossip-findings-postgres/src/`); that crate provides the canonical
> findings schema plan (table/index/column constants plus row projections),
> Rust-side tenant validation and duplicate folding that mirrors the SQL
> merge rules for observations, the concrete `FindingsSinkPg` backend and
> `FindingsConformanceProbe` count reader, a findings-specific migration set
> plus thin wrappers around the shared advisory-locked checksum-verifying
> runner and shared PostgreSQL test-support lifecycle, findings-specific
> type-mapping support, and a `FindingsPgMigrationError` alias re-exporting
> `PgMigrationError` from `gossip-pg-common`. Git runtime key/value storage,
> schema, migrations, and the concrete `GitPersistenceBackend`
> implementation live in `gossip-git-persistence-postgres`
> (`crates/gossip-git-persistence-postgres/src/`); that crate stores opaque
> scanner-owned keys and values for ref watermarks, seen bitmaps, and
> mid-scan checkpoints behind one PostgreSQL table plus the shared
> advisory-locked migration runner from `gossip-pg-common`.

Boundary 5 defines the persistence contracts for three subsystems:

- Coordination state (runs, shards, leases, fences, cursors, split state)
- Done-ledger (dedupe index: "was this object-version scanned under this policy?")
- Findings store (triage/query plane: findings + occurrences)

This is the normative reference for persistence backends behind:

- Coordination: `CoordinationBackend` (trait in `gossip-coordination/src/traits.rs`) + `PageCommit<S>` (worker commit protocol)
- Done-ledger: `DoneLedger`
- Findings: `FindingsSink`

Non-negotiables (project-wide):

- Never store or emit raw secret bytes (DB rows, logs, metrics, traces, errors, tests).
- Determinism: same bytes + same policy => same IDs and outputs.
- Idempotency: assume at-least-once execution; sinks dedupe by deterministic IDs.
- Multi-tenant isolation is correctness: strict tenant namespaces, explicit authz checks.

---

## 1. Rust types (implemented)

> Source: `crates/gossip-contracts/src/persistence/`.
> All types listed below are compiled code with unit and property
> tests. `conformance.rs` provides the backend-agnostic conformance harness
> (done-ledger, findings, and redaction checks).

### Traits

| Trait | Purpose | Key methods |
|-------|---------|-------------|
| `PersistenceFinding` | Unified finding-identity surface consumed by persistence translation, regardless of source family | `rule_id(&self) -> u32`, `norm_hash(&self) -> NormHash`, `blob_offset_start(&self) -> u64`, `blob_offset_end(&self) -> u64`, `blob_offset_len(&self) -> u64` |
| `DoneLedger` | Dedupe index: "was this object-version scanned under this policy?" | `batch_get(&self, TenantId, PolicyHash, &[OvidHash]) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error>`, `list_done_hashes(&self, TenantId, PolicyHash) -> Result<Vec<OvidHash>, Self::Error>`, `batch_upsert(&self, &[DoneLedgerRecord]) -> Result<Self::CommitHandle, Self::Error>` |
| `FindingsSink` | Triage/query plane: findings + occurrences + observations persistence | `upsert_batch(&self, FindingsUpsertBatch<'_>) -> Result<Self::CommitHandle, Self::Error>` |
| `CommitHandle` | Durable acknowledgement handle; `wait()` consumes self and returns a receipt | `wait(self) -> Result<Self::Receipt, Self::Error>` |
| `CommitReceipt` | Marker trait for durable persistence proof objects | Supertrait bounds: `Clone + Debug + Send + Sync + 'static` |
| `CoordinationBackend` | Shard lifecycle: acquire, renew, checkpoint, complete, park, split (lives in `gossip-coordination/src/traits.rs`, not in this module) | `acquire_and_restore_into`, `renew`, `checkpoint`, `complete`, `park_shard`, `split_residual`, `split_replace` |

### Typestate machine

| Type | Purpose |
|------|---------|
| `PageCommit<S>` | Compile-time enforcement of the commit protocol ordering: findings flush → done-ledger upsert → checkpoint boundary. State parameter `S` transitions through `AwaitingFindings` → `FindingsDurable` → `ItemDurable` → `CheckpointDurable`. Each state exposes only the transition methods valid for that stage; out-of-order calls are compile errors. |
| `CheckpointBoundaryKind` | Copy tag distinguishing ordered-content progress from repo-frontier progress. |
| `CheckpointBoundary` | Family-neutral checkpoint boundary: `OrderedContent(Cursor)` or `RepoFrontier(Cursor)`. Tags keep same-byte cursors from different source families distinct. |
| `CommitScope` | Immutable scope for a single page commit: tenant, policy hash, run, shard, fence epoch, committed-unit count, and tagged checkpoint boundary. Frozen at construction; every receipt-validation check (including checkpoint matching) compares against these values. |
| `WriteContext` | Shared runtime write scope: `tenant_id`, `policy_hash`, `run_id`, `shard_id`, `fence_epoch`. Runtime commit paths pass this copyable value once and let `ObservationRecord` / `DoneLedgerRecord` reconstruct the same routing and fencing metadata from durable fields. |

### Data types

**Done-ledger records** (`done_ledger.rs`, `ovid.rs`):

| Type | Purpose |
|------|---------|
| `DoneLedgerKey` | Composite lookup key: `(TenantId, PolicyHash, OvidHash)` — fixed-width, implements `CanonicalBytes`. |
| `DoneLedgerStatus` | Scan outcome enum with monotonic join-semilattice semantics: `FailedRetryable(1) < FailedPermanent(2) < Skipped(3) < ScannedClean(10) < ScannedWithFindings(11)`. `is_terminal()` groups the statuses that suppress future rescans (`FailedPermanent`, `Skipped`, and both scanned variants). Rank gap between 3 and 10 reserves space for future non-terminal states. |
| `DoneLedgerRecord` | Complete done-ledger row: key, lattice status, `bytes_scanned`, `findings_count`, provenance, optional error code. `try_new()` enforces the status/`findings_count` shape; write paths and `merge()` call `validate()` to enforce the full invariant set (e.g., non-scanned statuses require `error_code`). `ScannedClean` forces `findings_count = 0`; `ScannedWithFindings` keeps only `ScannedWithFindings` contributors and clamps to `>= 1`; provenance winner is the lexicographically greatest `(status, finished_at, started_at, fence_epoch, run_id, shard_id, error_code_bytes)` tuple. |
| `DoneLedgerProvenance` | Write-side metadata: `run_id`, `shard_id`, `fence_epoch`, `started_at`, `finished_at`. Not part of the dedup key. `from_write_context()` extracts the non-key fields from a `WriteContext`; `DoneLedgerRecord::write_context()` reconstructs the full scope by combining key + provenance. |
| `DoneLedgerErrorCode` | ASCII-safe bounded string (max 128 bytes) for structured error codes like `HTTP_403`, `TIMEOUT`. Validated alphabet at construction. |
| `OvidHash` | Content-addressed Object-Version Identity digest (BLAKE3, 32 bytes). Derived from `OvidHashInputs` via `derive_ovid_hash`. |
| `OvidHashInputs` | Structured inputs: `stable_item_id` + `version` (strong or weak `VersionId`). |

**Findings records** (`findings.rs`):

| Type | Purpose |
|------|---------|
| `FindingRecord` | Layer 1 — stable identity: `(tenant, stable_item_id, rule_fingerprint, secret_hash)`. Content-addressed `FindingId`. Version-independent and policy-independent. Never stores raw secrets. |
| `OccurrenceRecord` | Layer 2 — version-specific: pins a finding to an `ObjectVersionId` with `(byte_offset, byte_length)` span. `byte_length` guaranteed non-zero via `NonZeroU64`. Content-addressed `OccurrenceId`. |
| `ObservationRecord` | Layer 3 — policy- and run-scoped: records that an occurrence was seen under a specific `(policy_hash, run_id, shard_id, fence_epoch)` with associated `ovid_hash`. Optional display-safe `Location` metadata stored as `Option<Arc<Location>>` so that multiple observations sharing the same location avoid cloning the underlying `String` fields. `with_location(Arc<Location>)` attaches location; `location()` returns `Option<&Location>` (deref through Arc); `location_arc()` returns `Option<&Arc<Location>>` for cheap `Arc::clone` during merge loops. Content-addressed `ObservationId`. Runtime code can build one directly from `WriteContext`, and `write_context()` round-trips the stored routing/fencing fields back into the shared scope value. |
| `FindingsUpsertBatch<'a>` | Borrowed zero-copy batch view over all three layers. Provides `validate_referential_integrity()` for intra-batch consistency checks. |

Source-specific finding carriers do not flow into persistence directly. The
translation boundary consumes `PersistenceFinding`, which exposes only the
identity-relevant fields (`rule_id`, redacted `NormHash`, `blob_offset_start`,
`blob_offset_end`). Filesystem and Git paths are free to keep extra metadata such as
root hints, object paths, commit IDs, or confidence scores on their local
telemetry paths without affecting stable persistence identity.

**Commit receipts** (`commit.rs`):

| Type | Purpose |
|------|---------|
| `FindingsCommitReceipt` | Proves three-layer findings data is durable. Carries `finding_count`, `occurrence_count`, `observation_count`. |
| `DoneLedgerCommitReceipt` | Proves done-ledger rows are durable. Carries `record_count`, `scanned_count`, `findings_count`. |
| `CheckpointCommitReceipt` | Proves the checkpoint boundary is durable. Embeds a `CommitScope` and `checkpointed_at` timestamp; the typestate machine validates receipt-to-scope correspondence with a single equality check. |
| `ItemCommitReceipt` | Composite: findings + done-ledger. Assembled by `PageCommit` after validating ordering. |
| `PageCommitReceipt` | Terminal composite: item-commit + checkpoint. Sufficient proof that the checkpoint boundary can be safely advanced. |

**Typestate and error types** (`page_commit.rs`):

| Type | Purpose |
|------|---------|
| `AwaitingFindings` | Typestate: entry point, no durable acknowledgement yet. |
| `FindingsDurable` | Typestate: findings are durable; done-ledger is next. Carries `FindingsCommitReceipt`. |
| `ItemDurable` | Typestate: findings + done-ledger durable; checkpoint is next. Carries `ItemCommitReceipt`. |
| `CheckpointDurable` | Typestate: terminal state, all three stages durable. Carries `PageCommitReceipt`. |
| `PageCommitValidationError` | Receipt-vs-scope mismatch errors: `LedgerUnitCountMismatch` (done-ledger) and `CheckpointScopeMismatch` (checkpoint). |
| `CommitAdvanceError<E>` | Combined wait-or-validation error for `wait_*` transitions. |

**Shared error type** (`error.rs`):

| Type | Purpose |
|------|---------|
| `PersistenceInputError` | Validation errors for value types: empty fields, size limits, invalid bytes, zero spans, observation-id mismatch, inconsistent findings counts, missing/unexpected error codes, orphaned references, inconsistent tenants, provenance ordering. |

### Test doubles and adapters

| Type | Implements | Notes |
|------|-----------|-------|
| `ReadyCommitHandle<R, E>` | `CommitHandle` | Pre-resolved handle wrapping an already-computed `Result<R, E>`. `wait()` returns immediately. Used by synchronous backends and test doubles. Provides `ok()`, `err()`, and `from_result()` constructors. |
| `InMemoryDoneLedger` | `DoneLedger` | `HashMap`-backed reference implementation with configurable commit timing, injected failures, and lattice-merge semantics. Thread-safe via internal `Mutex`. Lives in `gossip-persistence-inmemory` crate. Passes `run_done_ledger_conformance`. |
| `InMemoryFindingsSink` | `FindingsSink` | `HashMap`-backed reference implementation with three-layer upsert, referential integrity checks, and configurable commit timing. Thread-safe via internal `Mutex`. Lives in `gossip-persistence-inmemory` crate. Passes `run_findings_conformance`. |
| `FindingsConformanceProbe` | (conformance-only trait) | Read-side probe for observing durable findings state; `pub` but not referenced by production code paths. The production `FindingsSink` API is write-only; this trait adds a narrow read surface so the conformance harness can snapshot row counts and prove replay does not duplicate rows. Backend crates implement this unconditionally (no `#[cfg(test)]` gate) so integration tests can exercise the real backend. |
| `run_conformance` | (harness entry point) | Backend-agnostic conformance harness exposed at `gossip_contracts::persistence::run_conformance` (also available via `persistence::conformance`). Verifies done-ledger idempotency and lattice merge, findings idempotency and referential integrity, and sensitive-type `Debug` redaction. Returns a `PersistenceConformanceReport` on success. |
| `run_done_ledger_conformance` | (harness entry point) | Done-ledger-only conformance harness exposed at `gossip_contracts::persistence::run_done_ledger_conformance` (also available via `persistence::conformance`). Runs five checks and returns `Result<u32, PersistenceConformanceError>` with `Ok(5)` when all done-ledger checks pass. |
| `run_findings_conformance` | (harness entry point) | Findings-only conformance harness exposed at `gossip_contracts::persistence::run_findings_conformance` (also available via `persistence::conformance`). Runs four checks (idempotent upsert, orphan occurrence rejection, orphan observation rejection, observation merge) and returns `Result<u32, PersistenceConformanceError>` with `Ok(4)` when all findings checks pass. Requires `FindingsSink + FindingsConformanceProbe`. |
| `run_redaction_conformance` | (harness entry point) | Redaction-only conformance harness exposed at `gossip_contracts::persistence::run_redaction_conformance` (also available via `persistence::conformance`). Runs three checks (`NormHash`, `SecretHash`, `FindingRecord` `Debug` redaction) and returns `Result<u32, PersistenceConformanceError>` with `Ok(3)`. Requires no backend instance. |

### Backend crates

| Crate | Scope | Notes |
|------|-------|-------|
| `gossip-pg-common` | Shared PostgreSQL type-mapping, migration, and test-support primitives | Owns `PgU64ConversionError`, the four `u64 ↔ BIGINT` conversion helpers (bit-pattern and ordered non-negative modes), `PgByteDecodeError` and `decode_fixed_32` for zero-copy `BYTEA` → `[u8; 32]` decoding, `EmbeddedMigration`, `MigrationConfig`, `PgMigrationError`, checksum-verification helpers, the shared advisory-locked migration runner, the `MigrationOperation` enum, and the shared PostgreSQL integration-test lifecycle (`create_test_db`, `test_client_bare`, `test_client_with`) used by the Postgres persistence crates. All PostgreSQL persistence backends depend on this crate instead of duplicating these primitives. |
| `gossip-done-ledger-postgres` | Synchronous PostgreSQL `DoneLedger` backend plus schema/migration/type-mapping support | Implements monotonic done-ledger upsert semantics with durable-before-return commits and provides the done-ledger migration set plus thin wrappers around the shared forward-only runner and shared PostgreSQL test-support lifecycle. Migration application remains checksum-verified, advisory-locked, and transaction-scoped, so migration SQL cannot use commands that require running outside a transaction block (for example `CREATE INDEX CONCURRENTLY`). Passes `run_done_ledger_conformance`. |
| `gossip-findings-postgres` | Synchronous PostgreSQL `FindingsSink` backend plus schema/migration/type-mapping/read-API support | Implements `FindingsSinkPg` with single-transaction findings → occurrences → observations upserts, prepared statement reuse, a `FindingsConformanceProbe` count reader, and tenant-scoped read helpers: `count_observations_by_tenant_policy` (returns `Vec<ObservationCountByPolicy>`) and `list_findings_needing_triage` (returns `Vec<PendingTriageFinding>` ordered by `seen_at DESC`). Read API result types live in `read_api.rs`. The crate also provides findings-specific schema constants, row projections, Rust-side tenant validation and duplicate folding that mirrors the observation SQL merge rules, and the findings migration set plus thin wrappers around the shared advisory-locked checksum-verifying runner and shared PostgreSQL test-support lifecycle. See [findings-postgres-dedup diagram](../../diagrams/21-findings-postgres-dedup.md) for the batch dedup pipeline, observation merge decision tree, and dual-convergence property. |
| `gossip-git-persistence-postgres` | Synchronous PostgreSQL `GitPersistenceBackend` plus schema/migration support for scanner-owned key/value state | Implements `GitPersistencePg` over a single `git_kv` table keyed by opaque `BYTEA` blobs. The backend preserves input order for `multi_get`, normalizes duplicate keys inside one `apply_batch` call with last-op-wins semantics, and commits the resulting put/delete set in one PostgreSQL transaction so `supports_atomic_batches()` can return `true`. The crate also owns the git-persistence migration set plus thin wrappers around the shared advisory-locked checksum-verifying runner and shared PostgreSQL test-support lifecycle. |

---

## 2. Cross-subsystem commit ordering (correctness-critical)

The worker-side commit protocol is mandatory and enforces correctness without cross-store transactions. The `PageCommit<S>` typestate machine makes this ordering a compile-time guarantee:

1. **`AwaitingFindings` → `FindingsDurable`**: Findings durable — `record_findings` / `wait_findings`
2. **`FindingsDurable` → `ItemDurable`**: Done-ledger durable — `record_done_ledger` / `wait_done_ledger` (validates item count)
3. **`ItemDurable` → `CheckpointDurable`**: Checkpoint boundary durable — `record_checkpoint` / `wait_checkpoint` (validates receipt scope equals page scope)

Consequences:

- If done-ledger says "Scanned," findings are already durable.
- Cursor never advances beyond what has been durably committed.
- Retries and reassignment are safe: idempotent sinks dedupe by deterministic IDs.
- Out-of-order calls are rejected at compile time, not runtime.

---

## 3. Recovery and failure behavior

- Coordination is authoritative for ownership and cursor.
- Done-ledger and findings are idempotent sinks; duplicates are safe.

Lease loss rule (hard):

- If a worker loses its lease or ownership key, it must stop scanning and must not checkpoint/split/complete/park.

Coordinator restart (durable etcd backend behavior):

- `EtcdCoordinator` and `AsyncEtcdCoordinator` persist run and shard state
  directly in etcd, then reload it through point reads, prefix scans, and
  active-index walks.
- After a coordinator process restart, workers reacquire shards against the
  persisted records, `fence_epoch` still fences stale workers, and progress
  resumes from the last durable cursor.

---

## 4. Anti-patterns (must not ship)

1. Do not ACK checkpoints before the coordination txn commits.
2. Do not implement coordination on a design that serializes hot fenced writes onto a single key/partition.
3. Do not create unbounded wide partitions for the done-ledger.
4. Do not store raw secret bytes in any persistence backend (including snippets). Store hashes and safe display fields only.
5. Do not partition done-ledger by shard id (ledger key is shard-independent).
6. Do not allow unbounded split fanout. Enforced by `MAX_SPLIT_CHILDREN` (hard cap per operation, `gossip-contracts/src/coordination/limits.rs`) and `DEFAULT_MAX_CHILDREN_PER_OP` (per-backend tunable, e.g. etcd config).
