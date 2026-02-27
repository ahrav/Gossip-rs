## Connector boundary plan for the distributed secret scanner

### 0. Goals and non-negotiables

- **Shard safety**: a worker enumerating `[start, end)` must never “leak” keys outside that range.
- **Resumability**: enumeration must resume from `last_key` even if any opaque pagination token is lost, stale, or invalid.
- **Bounded work**: both enumeration and reads must respect explicit budgets (items, bytes, deadlines).
- **Determinism (as defined)**: connectors must declare what “same run inputs” means via an explicit `EnumerationView` concept.
- **Toxic data handling**: never log raw keys, refs, or tokens. Only hashes or redacted forms.

Non-goals for v0

- Perfect exactly-once semantics for inherently mutable sources.
- Universal snapshotting across all sources. Instead: **define the view**, then test against it.

---

## 1. Boundary model and vocabulary

### 1.1 Concepts

- **ItemKey**: ordered byte string used for sharding, paging, and cursors. This is the “enumeration order key”.
- **ItemRef**: opaque credential-free handle used to open/read an item. Must not embed secrets.
- **StableId / VersionId**: identity and version claims for downstream dedupe and correctness.
- **EnumerationSpec**: defines the shard range and the declared enumeration view.
- **Cursor**: `(last_key, token?)` where `last_key` is the only durable resumption primitive.

### 1.2 Minimal API shape (contract surface)

```rust
// Enumerate ordered items within a shard range.
enumerate_page(spec: &EnumerationSpec, cursor: &Cursor, budgets: &Budgets)
  -> Result<(Vec<ScanItem>, Cursor), EnumerateError>;

// Open an item for reading.
open(item_ref: &ItemRef, budgets: &Budgets)
  -> Result<Reader, ReadError>;
```

---

## 2. Core value types (lock the surface first)

Implement these in `gossip_contracts::connector` (doc-first, code immediately after).

### 2.1 Types

- `ItemKey`
  - `Vec<u8>` or small-bytes wrapper
  - total ordering = lexicographic over bytes
  - max length cap (hard limit)

- `ItemRef`
  - opaque bytes
  - **no `Debug`** or only hashed/redacted `Debug`
  - max length cap

- `StableId`
  - string-ish with validation and length cap

- `VersionId`
  - `Strong(bytes)` or `Weak(bytes)` with length cap

- `ContentHints`, `Location` (optional, but define now if needed for scheduling/telemetry)
- `ScanItem`
  - `{ item_key, item_ref, stable_id?, version_id?, hints?, location? }`

- `Cursor`
  - `{ last_key: ItemKey, token: Option<TokenBytes> }`
  - `TokenBytes` has caps and redacted debug

- `Budgets`
  - v0: `{ max_items, max_bytes, deadline }`

### 2.2 Redaction rules (mandatory)

- Any of: `ItemKey`, `ItemRef`, `Cursor.token` must be treated as **toxic**
- Logging/tracing must use:
  - `hash(key)` / `hash(ref)` / `hash(token)`
  - optionally `len` and first N bytes of the hash, never raw bytes

---

## 3. Enumeration invariants (formal spec)

Given:

`enumerate_page(spec, cursor, budgets) -> (items, next_cursor)`

### 3.1 Page-level invariants

1. **Membership (shard safety)**
   - For every `item.item_key`: `spec.contains_key(item_key)` must be true
   - Interpretation: `item_key ∈ [start, end)` under lex order

2. **Ordered output**
   - `items[i].item_key <= items[i+1].item_key` (non-decreasing)

3. **Cursor consistency**
   - If `items` non-empty: `next_cursor.last_key >= last(items).item_key`
   - Cursor must be monotonic relative to input: `next_cursor.last_key >= cursor.last_key`

4. **Resumable by key (token may fail)**
   - If `cursor.token` missing/invalid/stale: connector must still resume from `cursor.last_key` alone
   - Concrete behavior: “start strictly after `cursor.last_key`” must work

5. **Determinism relative to an EnumerationView**
   - Under a fixed declared view, same inputs yield the same ordered stream of keys
   - If the source is mutable, the connector must define what “view” is (and the runtime treats that as run configuration)

### 3.2 Empty page semantics (pick and encode now)

You need a strict rule here to avoid infinite loops and silent gaps. Recommended v0 rule:

- Empty `items` is allowed only if one of:
  - end-of-range reached, or
  - budgets/deadline forced early return

- If `items` is empty, **cursor must not advance** (`next_cursor.last_key == cursor.last_key`)
- Token may change, but resumption must still work without it

If you choose different semantics, encode it in the validator and harness.

---

## 4. Read invariants (formal spec)

Given:

`open(item_ref, budgets) -> reader`

The connector must ensure:

- **Credential-free handle**
  - `ItemRef` must not require embedded credentials to function
  - Credentials live only in connector configuration / runtime context

- **Version correctness**
  - If the connector claims `VersionId::Strong`, `open()` must read the bytes for that specific `(stable_id, version)` pair
  - If `Weak`, connector is allowed weaker guarantees, but must state the consequences (dedupe strategy relies on this)

- **Budget compliance**
  - Enforce max bytes, deadline/timeouts, and any connector-specific limits
  - “Bounded” is the requirement; exact policy can be refined later

---

## 5. Failure behavior rules (must be uniform)

- **Fail loud on contract unsafety**
  - If enumeration cannot prove shard safety or resumability by key, return a typed error
  - Never “best-effort skip” a key or page silently

- **Lease/ownership loss**
  - If lease is lost later in the runtime (Phase IV), the worker must pause/abort enumeration rather than risk overlap
  - Principle: better pause than overlap

- **Toxic logging**
  - Never log raw `item_ref`, `item_key`, tokens
  - Errors may include hashed identifiers for debugging

Strong recommendation: define an error taxonomy that makes “unsafe to proceed” unignorable:

- `EnumerateError::ContractViolation(...)` (fatal, stop)
- `EnumerateError::Transient(...)` (retryable)
- `EnumerateError::Auth(...)` (stop and surface)
- Similar split for reads

---

## 6. Conformance harness (build first, enforce forever)

This is the connector test kit that prevents “3 connectors later we learned the contract was wrong.”

### 6.1 Page validator unit tests

Validator: `validate_page(spec, input_cursor, items, next_cursor) -> Result<(), ContractError>`

Tests must reject:

- out-of-range keys
- unsorted pages
- `next_cursor.last_key < last_item_key`
- cursor regression: `next_cursor.last_key < input_cursor.last_key`
- empty-page violations (based on your chosen semantics)

### 6.2 Property tests: resumability and token corruption

Generate deterministic key streams and check:

- pagination + checkpoints + random restarts eventually enumerate the same suffix
- inject token corruption or token removal at arbitrary steps
- require successful fallback to `last_key`-only resume

### 6.3 No-dup/no-gap checks (relative to declared view)

- Deterministic connectors (fixed view): assert exactly-once enumeration within `[start,end)`
- Mutable connectors: assert only shard bounds + monotonic cursor + ordering
  - rely on higher-level at-least-once scanning and downstream dedupe ledger later

### 6.4 Credential-free `ItemRef` tests (best-effort)

- Ensure serialized `ItemRef` does not contain:
  - obvious patterns: `Authorization:`, `Bearer `, `AKIA`, etc.
  - connector-configured secret canaries (inject a sentinel into credentials and verify it never appears in `ItemRef` bytes)

### 6.5 Determinism tests

- Same seed/config/view -> same ordered keys and same `(stable_id, version_id)` claims
- (Scaffolding now, full wiring later): same bytes + same policy -> same derived `FindingId`

---

## 7. Chunked work plan (dependency order, each chunk leaves the system better)

### Chunk 0 - Rename the identity type to eliminate collisions (worth the break)

Goal: prevent confusion between:

- enumeration order key used for sharding/cursors, and
- identity key material used for `StableItemId` derivation

Action:

- Rename `identity::ItemKey` to `IdentityKey` (or `ItemIdentityKey`)
- Keep `StableItemId` derivation unchanged, update callsites and tests

Done criteria:

- No duplicate “ItemKey” concepts in the codebase
- All existing tests compile and pass after rename

### Chunk 1 - Define connector-facing value types (doc-first, then code)

Implement `gossip_contracts::connector` types:

- `ItemKey`, `ItemRef`, `StableId`, `VersionId`, `Cursor`, `Budgets`, `ScanItem`, optional hints/location
- size caps and redacted/hash-only debug

Done criteria:

- Public surface compiles
- Size caps enforced
- Debug/logging cannot accidentally print raw toxic bytes

### Chunk 2 - Define connector traits plus capability flags

Implement traits:

- `EnumerationConnector::enumerate_page`
- `ReadConnector::open`

Capabilities:

- `resume_by_key: bool` (should be required true for most connectors)
- `range_read/seek: bool` (optional for later optimization)
- Any additional planning flags you actually need (keep minimal)

Done criteria:

- Runtime can query connector capabilities
- Budget struct is plumbed end-to-end (even if basic)

### Chunk 3 - Build the page validator (hard gate)

Implement:

- `validate_page(spec, input_cursor, items, next_cursor)`

Integrate it into:

- conformance tests (mandatory)
- worker runtime enumeration path (mandatory)

Done criteria:

- Validator rejects all invalid cases via unit tests
- Worker runtime refuses to proceed on contract violation

### Chunk 4 - Build the conformance harness (connector test kit)

Implement reusable harness that runs:

- validator checks
- property tests (resumption, token corruption)
- optional determinism and no-credential assertions

Done criteria:

- Harness is easy to import from connector crates
- CI enforces it for all connectors

### Chunk 5 - Implement 1 to 2 reference connectors

Start with:

- `InMemoryDeterministicConnector` (gold standard for tests)
- `FilesystemConnector` (real-ish, simple lex ordering)

Done criteria:

- Both pass harness
- Filesystem connector defines its ordering key clearly and deterministically

### Chunk 6 - Integrate into worker runtime (Phase IV wiring)

Only after harness-passing connectors exist:

- wire enumeration and read calls through the boundary
- enforce validator checks in runtime
- ensure lease-loss behavior pauses/aborts safely
- ensure logs are hash-only for toxic fields

Done criteria:

- Runtime trusts contract, not connector “vibes”
- No connector-specific glue leaks into runtime beyond the contract types and traits

---

## 8. Acceptance criteria for the boundary (what “done” means)

- Every connector must pass the conformance harness in CI.
- Runtime enforces `validate_page` on every page before acting on it.
- Token loss or corruption does not prevent resumption (key-only resume works).
- No raw keys/refs/tokens appear in logs or traces (spot-check via tests plus grep rules).
- For connectors claiming `Strong` versioning, reads are stable for the claimed `(stable_id, version)`.

---

## 9. Two places to be strict now (or you will pay later)

- **Empty page semantics**: choose one rule and encode it. Ambiguity here creates infinite loops, silent gaps, or both.
- **EnumerationView**: mutable sources must declare what they can guarantee. If you hand-wave “determinism” without a view definition, the harness becomes meaningless.

This outline should drop cleanly into a design doc and map 1:1 to tickets.
