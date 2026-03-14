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
> runner and shared PostgreSQL test-support lifecycle, and findings-specific
> type-mapping support.

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
| `DoneLedger` | Dedupe index: "was this object-version scanned under this policy?" | `batch_get(&self, TenantId, PolicyHash, &[OvidHash]) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error>`, `batch_upsert(&self, &[DoneLedgerRecord]) -> Result<Self::CommitHandle, Self::Error>` |
| `FindingsSink` | Triage/query plane: findings + occurrences + observations persistence | `upsert_batch(&self, FindingsUpsertBatch<'_>) -> Result<Self::CommitHandle, Self::Error>` |
| `CommitHandle` | Durable acknowledgement handle; `wait()` consumes self and returns a receipt | `wait(self) -> Result<Self::Receipt, Self::Error>` |
| `CommitReceipt` | Marker trait for durable persistence proof objects | Supertrait bounds: `Clone + Debug + Send + Sync + 'static` |
| `CoordinationBackend` | Shard lifecycle: acquire, renew, checkpoint, complete, park, split (lives in `gossip-coordination/src/traits.rs`, not in this module) | `acquire_and_restore_into`, `renew`, `checkpoint`, `complete`, `park_shard`, `split_residual`, `split_replace` |

### Typestate machine

| Type | Purpose |
|------|---------|
| `PageCommit<S>` | Compile-time enforcement of the commit protocol ordering: findings flush → done-ledger upsert → cursor checkpoint. State parameter `S` transitions through `AwaitingFindings` → `FindingsDurable` → `ItemDurable` → `CheckpointDurable`. Each state exposes only the transition methods valid for that stage; out-of-order calls are compile errors. |
| `PageCommitScope` | Immutable scope for a single page commit: tenant, run, shard, fence epoch, item count, and cursor boundary. Frozen at construction; every receipt-validation check compares against these values. |

### Data types

**Done-ledger records** (`done_ledger.rs`):

| Type | Purpose |
|------|---------|
| `DoneLedgerKey` | Composite lookup key: `(TenantId, PolicyHash, OvidHash)` — fixed-width, implements `CanonicalBytes`. |
| `DoneLedgerStatus` | Scan outcome enum with monotonic join-semilattice semantics: `FailedRetryable(1) < FailedPermanent(2) < Skipped(3) < ScannedClean(10) < ScannedWithFindings(11)`. Rank gap between 3 and 10 reserves space for future non-terminal states. |
| `DoneLedgerRecord` | Complete done-ledger row: key, lattice status, `bytes_scanned`, `findings_count`, provenance, optional error code. Validated at construction (`try_new`) and optionally via `validate()` before persisting. Supports `merge` for lattice upsert. |
| `DoneLedgerProvenance` | Write-side metadata: `run_id`, `shard_id`, `fence_epoch`, `started_at`, `finished_at`. Not part of the dedup key. |
| `DoneLedgerErrorCode` | ASCII-safe bounded string (max 128 bytes) for structured error codes like `HTTP_403`, `TIMEOUT`. Validated alphabet at construction. |
| `OvidHash` | Content-addressed Object-Version Identity digest (BLAKE3, 32 bytes). Derived from `OvidHashInputs` via `derive_ovid_hash`. |
| `OvidHashInputs` | Structured inputs: `stable_item_id` + `version` (strong or weak `VersionId`). |

**Findings records** (`findings.rs`):

| Type | Purpose |
|------|---------|
| `FindingRecord` | Layer 1 — stable identity: `(tenant, stable_item_id, rule_fingerprint, secret_hash)`. Content-addressed `FindingId`. Version-independent and policy-independent. Never stores raw secrets. |
| `OccurrenceRecord` | Layer 2 — version-specific: pins a finding to an `ObjectVersionId` with `(byte_offset, byte_length)` span. `byte_length` guaranteed non-zero via `NonZeroU64`. Content-addressed `OccurrenceId`. |
| `ObservationRecord` | Layer 3 — policy- and run-scoped: records that an occurrence was seen under a specific `(policy_hash, run_id, shard_id, fence_epoch)` with associated `ovid_hash`. Optional display-safe `Location` metadata. Content-addressed `ObservationId`. |
| `FindingsUpsertBatch<'a>` | Borrowed zero-copy batch view over all three layers. Provides `validate_referential_integrity()` for intra-batch consistency checks. |

**Commit receipts** (`commit.rs`):

| Type | Purpose |
|------|---------|
| `FindingsCommitReceipt` | Proves three-layer findings data is durable. Carries `finding_count`, `occurrence_count`, `observation_count`. |
| `DoneLedgerCommitReceipt` | Proves done-ledger rows are durable. Carries `record_count`, `scanned_count`, `findings_count`. |
| `CheckpointCommitReceipt` | Proves cursor checkpoint is durable. Embeds a `PageCommitScope` and `checkpointed_at` timestamp; the typestate machine validates receipt-to-scope correspondence with a single equality check. |
| `ItemCommitReceipt` | Composite: findings + done-ledger. Assembled by `PageCommit` after validating ordering. |
| `PageCommitReceipt` | Terminal composite: item-commit + checkpoint. Sufficient proof that the cursor can be safely advanced. |

**Typestate and error types** (`page_commit.rs`):

| Type | Purpose |
|------|---------|
| `AwaitingFindings` | Typestate: entry point, no durable acknowledgement yet. |
| `FindingsDurable` | Typestate: findings are durable; done-ledger is next. Carries `FindingsCommitReceipt`. |
| `ItemDurable` | Typestate: findings + done-ledger durable; checkpoint is next. Carries `ItemCommitReceipt`. |
| `CheckpointDurable` | Typestate: terminal state, all three stages durable. Carries `PageCommitReceipt`. |
| `PageCommitValidationError` | Receipt-vs-scope mismatch errors: `LedgerItemCountMismatch` (done-ledger) and `CheckpointScopeMismatch` (checkpoint). |
| `CommitAdvanceError<E>` | Combined wait-or-validation error for `wait_*` transitions. |

**Shared error type** (`error.rs`):

| Type | Purpose |
|------|---------|
| `PersistenceInputError` | Validation errors for value types: empty fields, size limits, invalid bytes, zero spans, observation-id mismatch, inconsistent findings counts, missing/unexpected error codes, orphaned references, inconsistent tenants, provenance ordering. |

### Test doubles and adapters

| Type | Implements | Notes |
|------|-----------|-------|
| `ReadyCommitHandle<R, E>` | `CommitHandle` | Pre-resolved handle wrapping an already-computed `Result<R, E>`. `wait()` returns immediately. Used by synchronous backends and test doubles. Provides `ok()`, `err()`, and `from_result()` constructors. |
| `InMemoryDoneLedger` | `DoneLedger` | `HashMap`-backed reference implementation with configurable commit timing, injected failures, and lattice-merge semantics. Thread-safe via internal `Mutex`. Lives in `gossip-persistence-inmemory` crate. Passes `run_conformance`. |
| `InMemoryFindingsSink` | `FindingsSink` | `HashMap`-backed reference implementation with three-layer upsert, referential integrity checks, and configurable commit timing. Thread-safe via internal `Mutex`. Lives in `gossip-persistence-inmemory` crate. Passes `run_conformance`. |
| `FindingsConformanceProbe` | (test-only trait) | Test-only read-side probe for observing durable findings state. The production `FindingsSink` API is write-only; this trait adds a narrow read surface so the conformance harness can snapshot row counts and prove replay does not duplicate rows. Backend crates implement this on their test double or integration-test wrapper. |
| `run_conformance` | (harness entry point) | Backend-agnostic conformance harness exposed at `gossip_contracts::persistence::run_conformance` (also available via `persistence::conformance`). Verifies done-ledger idempotency and lattice merge, findings idempotency and referential integrity, and sensitive-type `Debug` redaction. Returns a `PersistenceConformanceReport` on success. |
| `run_done_ledger_conformance` | (harness entry point) | Done-ledger-only conformance harness exposed at `gossip_contracts::persistence::run_done_ledger_conformance` (also available via `persistence::conformance`). Runs four checks and returns `Result<u32, PersistenceConformanceError>` with `Ok(4)` when all done-ledger checks pass. |
| `run_findings_conformance` | (harness entry point) | Findings-only conformance harness exposed at `gossip_contracts::persistence::run_findings_conformance` (also available via `persistence::conformance`). Runs four checks (idempotent upsert, orphan occurrence rejection, orphan observation rejection, observation merge) and returns `Result<u32, PersistenceConformanceError>` with `Ok(4)` when all findings checks pass. Requires `FindingsSink + FindingsConformanceProbe`. |
| `run_redaction_conformance` | (harness entry point) | Redaction-only conformance harness exposed at `gossip_contracts::persistence::run_redaction_conformance` (also available via `persistence::conformance`). Runs three checks (`NormHash`, `SecretHash`, `FindingRecord` `Debug` redaction) and returns `Result<u32, PersistenceConformanceError>` with `Ok(3)`. Requires no backend instance. |

### Backend crates

| Crate | Scope | Notes |
|------|-------|-------|
| `gossip-pg-common` | Shared PostgreSQL type-mapping, migration, and test-support primitives | Owns `PgU64ConversionError`, the four `u64 ↔ BIGINT` conversion helpers (bit-pattern and ordered non-negative modes), `PgByteDecodeError` and `decode_fixed_32` for zero-copy `BYTEA` → `[u8; 32]` decoding, `EmbeddedMigration`, `MigrationConfig`, `PgMigrationError`, checksum-verification helpers, the shared advisory-locked migration runner, the `MigrationOperation` enum, and the shared PostgreSQL integration-test lifecycle (`create_test_db`, `test_client_bare`, `test_client_with`) used by the Postgres persistence crates. All PostgreSQL persistence backends depend on this crate instead of duplicating these primitives. |
| `gossip-done-ledger-postgres` | Synchronous PostgreSQL `DoneLedger` backend plus schema/migration/type-mapping support | Implements monotonic done-ledger upsert semantics with durable-before-return commits and provides the done-ledger migration set plus thin wrappers around the shared forward-only runner and shared PostgreSQL test-support lifecycle. Migration application remains checksum-verified, advisory-locked, and transaction-scoped, so migration SQL cannot use commands that require running outside a transaction block (for example `CREATE INDEX CONCURRENTLY`). Passes `run_done_ledger_conformance`. |
| `gossip-findings-postgres` | Synchronous PostgreSQL `FindingsSink` backend plus schema/migration/type-mapping support | Implements `FindingsSinkPg` with single-transaction findings → occurrences → observations upserts, prepared statement reuse, a `FindingsConformanceProbe` count reader, and tenant-scoped read helpers for grouped observation counts and latest-observation triage listing. The crate also provides findings-specific schema constants, row projections, Rust-side tenant validation and duplicate folding that mirrors the observation SQL merge rules, and the findings migration set plus thin wrappers around the shared advisory-locked checksum-verifying runner and shared PostgreSQL test-support lifecycle. See [findings-postgres-dedup diagram](../../diagrams/21-findings-postgres-dedup.md) for the batch dedup pipeline, observation merge decision tree, and dual-convergence property. |

---

## 2. Cross-subsystem commit ordering (correctness-critical)

The worker-side commit protocol is mandatory and enforces correctness without cross-store transactions. The `PageCommit<S>` typestate machine makes this ordering a compile-time guarantee:

1. **`AwaitingFindings` → `FindingsDurable`**: Findings durable — `record_findings` / `wait_findings`
2. **`FindingsDurable` → `ItemDurable`**: Done-ledger durable — `record_done_ledger` / `wait_done_ledger` (validates item count)
3. **`ItemDurable` → `CheckpointDurable`**: Cursor checkpoint durable — `record_checkpoint` / `wait_checkpoint` (validates receipt scope equals page scope)

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

Coordinator restart (contract for durable backends; not yet implemented):

- Reload state from coordination backend via prefix scans + indexes.
- Workers reacquire shards, `fence_epoch` bumps, and resume from last durable cursor.

> **Note:** The `EtcdCoordinator` currently delegates to an `InMemoryCoordinator`,
> so state is lost on process restart. The recovery protocol above describes the
> required contract for durable backends, not current behavior.

---

## 4. Anti-patterns (must not ship)

1. Do not ACK checkpoints before the coordination txn commits.
2. Do not implement coordination on a design that serializes hot fenced writes onto a single key/partition.
3. Do not create unbounded wide partitions for the done-ledger.
4. Do not store raw secret bytes in any persistence backend (including snippets). Store hashes and safe display fields only.
5. Do not partition done-ledger by shard id (ledger key is shard-independent).
6. Do not allow unbounded split fanout. Enforced by `MAX_SPLIT_CHILDREN` (hard cap per operation, `gossip-contracts/src/coordination/limits.rs`) and `DEFAULT_MAX_CHILDREN_PER_OP` (per-backend tunable, e.g. etcd config).
