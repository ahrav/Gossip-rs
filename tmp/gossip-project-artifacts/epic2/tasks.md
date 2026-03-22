## Task list

### 1) Fix filesystem identity and tag correctness

Scope: clean up any filesystem-specific identity bugs that would poison done-ledger/findings correctness before you touch resume or commit logic.

Why this is a separate task: the persistence outline calls out a current collision risk where filesystem stable IDs are derived from connector tag plus relative path only, which collides across different roots. It also calls out ad hoc connector tags in runtime. Both must be corrected before you trust ledger skips or findings dedupe across multiple filesystem roots.

In:

- include `connector_instance_id` in filesystem `StableItemId` derivation,
- unify runtime and connector tag usage to the canonical filesystem connector tag,
- add regression tests for same-path/different-root isolation.

Out:

- no page-fill or runtime loop work yet.

Acceptance:

- two different filesystem instances with the same relative path do not collide in stable identity,
- runtime identity derivation uses the same tag constant as the connector.

### 2) Finalize `FilesystemConnector` on the ordered-content contract

Scope: make the connector itself contract-complete before more runtime wiring.

In:

- deterministic `ItemKey` ordering,
- credential-free `ItemRef`,
- version claim behavior (`Strong` vs `Weak`) made explicit,
- budget-respecting `open()` behavior,
- toxic-field redaction on debug/log surfaces.

Out:

- no checkpointing or done-ledger logic.

Acceptance:

- connector exposes ordered pages and reads that satisfy the connector boundary invariants.

### 3) Make filesystem resume real and key-authoritative

Scope: remove any fake cursor plumbing and make filesystem paging resumable from `last_key` alone.

In:

- durable cursor semantics based on `last_key`,
- optional token support only as a non-authoritative fast path,
- strict exhausted-empty semantics,
- explicit non-empty final-page behavior.

Out:

- no distributed reassignment handling yet.

Acceptance:

- token loss or corruption does not prevent correct resume,
- empty pages do not advance the authoritative cursor,
- resumption starts strictly after `last_key`.

### 4) Add filesystem connector conformance coverage

Scope: make the filesystem connector prove it obeys the ordered-content contract before you trust it in distributed runtime tests.

In:

- ordering tests,
- shard-range membership tests,
- token fallback tests,
- determinism tests for a fixed view,
- `ItemRef` credential-canary tests,
- empty-page and final-page semantics tests.

Out:

- runtime lease/reassignment tests.

Acceptance:

- filesystem passes the same validator/harness shape the connector plan requires,
- CI will fail on contract regression before runtime integration breaks.

### 5) Wire `OrderedContentSource` page fill on the real runtime

Scope: complete the runtime’s page acquisition and validation loop in `ordered_content.rs`.

In:

- lease acquisition/restore,
- `fill_page`,
- page validation before downstream use,
- connector error classification into fatal vs retryable vs unsafe-to-proceed,
- immediate stop on lease uncertainty.

Out:

- no ledger prefilter or commit path in this task.

Acceptance:

- runtime can acquire a filesystem shard, fill a page, validate it, and either emit work or stop safely on contract/lease failure.

6. **Filesystem request model + normalization**
   Accept `single_file` and `directory_root` requests and lower them into a canonical `RunSpec`, filesystem source config, and initial shard plan. This becomes the public MVP submission contract for filesystem scans.

7. **Filesystem initial shard geometry planner**
   Encode the MVP geometry rules: `single_file -> one shard`; `directory_root -> one initial shard over the root`; use residual splits later for scale-out instead of pre-sharding. Keep this planner deterministic so the same request lowers the same way every time.

8. **Filesystem shard payload schema + runtime hydration**
   Define exactly what filesystem metadata is packed into shard records—root path, source mode, and any initial bounds—and make the worker reconstruct the same connector config and ordered range from that payload. This is where control-plane state becomes authoritative enough for shard safety and key-based resume.

9. **Coordination-backed run creation + shard registration flow**
   Implement the first real control-plane write path over existing coordination APIs: `create_run(...)` plus `register_shards(...)`. The acceptance bar here is that workers only see a fully registered run/shard set, consistent with the existing run lifecycle.

10. **Minimal filesystem submission entrypoint**
    Add the first real submission surface for filesystem scans—CLI, API handler, or service entrypoint—that accepts file/directory requests and invokes normalization + run/shard registration. Keep it minimal and filesystem-specific for Epic 2.

11. **Filesystem submission/control-plane integration tests**
    Cover request normalization, initial shard geometry selection, shard metadata round-trip, `create_run`/`register_shards` integration, and request -> run -> shard -> worker-claim happy path. This is the control-plane proof for the Epic 2 deliverable “filesystem request -> run -> shard registration flow.”

12. **Ordered-content done-ledger prefilter**
    Batch-check page items against the done ledger before open/scan so a page is split into “already done” versus “scan miss” work.

13. **Filesystem read/open + scan execution on bounded budgets**
    Consume validated scan misses under explicit byte, time, and in-flight limits.

14. **Durable per-item findings + done-ledger commit path**
    Commit findings first, then done ledger, and emit an item receipt only after durability.

15. **Receipt-driven committed-prefix checkpointing**
    Advance the cursor only from the committed prefix implied by durable item receipts.

16. **Explicit shard completion semantics**
    Make exhausted-empty and non-empty-final-page completion cases explicit and safe.

17. **Lease-loss and reassignment recovery**
    Stop quickly on lease uncertainty and resume from last committed progress after reassignment. The boundary contract explicitly prefers pause/abort over risking overlap.

18. **Real filesystem end-to-end harness on etcd + Postgres**
    Exercise the whole path: request -> run -> shard registration -> worker claim -> findings/done-ledger/checkpoint.

19. **Bounded-memory / slow-sink proof**
    Verify queues and buffers remain bounded when findings or done-ledger commits slow down.

20. **Filesystem distributed failure suite**
    End-to-end cases for ordering, range membership, token fallback, prefix commit, exhausted-empty behavior, non-empty final page behavior, lease loss mid-page, and retry after reassignment.

## Why this cut is cleaner

This gives you two clear vertical slices:

- **Tasks 6–11:** request -> run -> shard registration -> worker claim
- **Tasks 12–20:** claim -> enumerate -> scan -> durable commit -> checkpoint -> completion/failure proof

That matches the revised Epic 2 exit criteria: a file/directory request can create runs and shards in etcd, workers can claim and execute those shards, and checkpoints advance only from committed receipts.

I would **leave** duplicate-submission safety, replay-safe registration, and stricter run/shard metadata validation in the later hardening bucket. The current plan already places those under the production-hardening epic, and keeping them there preserves a smaller, more coherent Epic 2 MVP slice.

The next design pass should start with **task 6**, because it fixes the public request contract before you write registration code.
