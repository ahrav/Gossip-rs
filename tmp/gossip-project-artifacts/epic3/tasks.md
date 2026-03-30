The shortest safe path is to implement Epic 3 as three narrow additions, not as a broad runtime rewrite:

1. a Git control-plane path that mirrors the existing filesystem submission flow,
2. a repo-frontier worker path that reuses the current lease/checkpoint machinery,
3. a `scanner-git` adapter that owns inner Git persistence while the outer runtime only owns repo-frontier progress.

That matches the stated Epic 3 scope, keeps coordination state proportional to repo shards rather than commits/blobs, and preserves the existing contract rules around ordered paging, key-authoritative resume, bounded work, and “no early ACK.”

## Scope

In scope for this plan:

- local/static Git inputs only
- submission path for repo / repo list / repo + refs / repo + commit
- repo-frontier shard creation and worker execution
- deterministic mirror management
- `scanner-git` execution and persistence integration
- clean separation between outer repo progress and inner Git scan state

Out of scope for this epic:

- hosted provider discovery
- multi-repo balancing inside a shard beyond the initial one-target-per-shard geometry
- read/query plane work
- broad observability platform work beyond the minimum signals needed to operate Git MVP

## Assumptions

I am assuming the following and designing around them:

- Epic 3 should run on the real MVP backends already chosen for the project, not on a repo-local-only fallback.
- For MVP, one normalized repo target becomes one initial shard. Repo lists therefore become many shards, not one large shard.
- Selection belongs in shard payload or execution payload, not in `RepoKey`.
- Local/static worker hosts are Unix-like; local path canonicalization can therefore be made deterministic.
- A repo execution must produce a durable receipt before outer checkpoint advancement. That follows the project’s no-early-ACK rule.

## Recommended design to lock now

### 1) Outer unit of work is a repo target, not an object inside the repo

Use repo-frontier only for scheduling and checkpointing across repositories. Do not try to represent commits, blobs, or files in etcd. That keeps coordination state at `O(shards)` rather than `O(objects)`.

Pattern: frontier-based crawling + fenced leases.

Alternative: push inner Git objects into the outer frontier.
Tradeoff: more uniform model, but materially worse state explosion and much harder reasoning.

### 2) One initial shard per normalized repo target

For local/static MVP, do not pre-build multi-target shard packing. A request with 200 repos should create 200 initial repo-frontier shards. That is exactly the simplest geometry the Epic text points at.

Pattern: KCL-style shard ownership, but with repo targets as units.

Alternative: pack many repos into one shard now.
Tradeoff: fewer etcd records, but much more complexity around split points, replay, and checkpointing for little immediate value.

### 3) `RepoKey` is repo identity only

`RepoKey` should encode canonical repo identity, not selection. Refs and explicit commits should live in shard metadata / execution payload. That keeps ordering stable and avoids selection changes mutating scheduling identity.

Alternative: put selection into the key.
Tradeoff: easier uniqueness for same-repo/multi-selection cases, but worse ordering semantics and harder future provider compatibility.

### 4) Explicit commit targets should be lowered to synthetic refs in the mirror

`scanner-git` already thinks in terms of start sets / refs, and stable ref naming matters for stable watermark keys. So explicit commit inputs should lower to a stable synthetic ref in a private mirror namespace, not a one-off direct commit execution path.

Pattern: synthetic ref indirection.

Alternative: teach the executor a raw-commit mode.
Tradeoff: less Git ref manipulation, but it forks the inner execution model and weakens watermark stability.

### 5) Do not force `scanner-git` through the ordered-content committer

The hardest seam in this epic is durability. The outer runtime already has checkpointing machinery, but `scanner-git` has its own atomic finalize semantics. My recommendation is to add a narrow repo-family durable-receipt seam rather than pretending a repo execution is the same as an ordered-content item commit.

Pattern: checkpoint + idempotent sink, with repo-level durable receipt.

Alternative: translate every inner Git action into the existing ordered-content commit path immediately.
Tradeoff: more uniform, but much larger refactor and higher risk of violating inner watermark semantics.

## Ticket outline

Below is the plan cut into ticket-sized units.

---

### Ticket 1 — Freeze the Git MVP execution model

**Scope**

Lock the architectural seam for Git MVP before implementation spreads.

**Decision**

- Outer scheduling/checkpoint unit = one repo target.
- Outer checkpoint = repo frontier only.
- Inner progress = `scanner-git` watermark / seen / persistence state only.
- One normalized repo target = one initial shard.
- No hosted discovery.
- No multi-selection-per-repo within one run for MVP.

**Deliverables**

- ADR or design note in repo
- explicit state machine for:
  - `Unclaimed -> Claimed -> Executing -> InnerDurable -> OuterCheckpointed -> Completed`

- error taxonomy:
  - retryable
  - fatal input/config
  - stale-owner / lease-loss stop

**Acceptance**

- Team agrees on one durable-receipt seam
- Team agrees that selection does not live in `RepoKey`
- Team agrees duplicate same-repo/different-selection submissions are rejected for MVP

**Why this ticket matters**

Without this, the implementation will oscillate between “Git as another ordered-content connector” and “Git as a repo-family runtime,” which will waste time.

---

### Ticket 2 — Finalize `RepoKey` encoding, ordering, and stable `repo_id` derivation

**Scope**

Define the canonical identity and sort order for local/static repos.

**Decision**

Recommended `RepoKey` shape for local/static MVP:

- one-byte locator kind prefix
- canonical absolute repo path bytes
- no selection fields

Also define a stable `repo_id` for inner `scanner-git` persistence, derived deterministically from tenant scope + normalized repo identity.

**Deliverables**

- canonical path normalization function
- `RepoKey` encode/decode helpers
- total ordering tests
- stable `repo_id` derivation helper
- submission-time collision detection within a normalized request

**Acceptance**

- same repo path normalizes to one `RepoKey`
- equivalent path spellings dedupe
- sorted repo lists are stable across process restarts
- same normalized repo produces same `repo_id`
- raw repo path is never logged directly

**Performance note**

Request normalization cost is `O(R log R)` for `R` repos. Runtime lookup should be `O(1)` per single-target shard.

---

### Ticket 3 — Add typed Git submission request models and normalization

**Scope**

Create the request model for:

- single repo
- repo list
- repo + explicit refs
- repo + explicit commit

**Decision**

Normalize all incoming requests into:

- `NormalizedGitTarget`
  - `RepoKey`
  - `RepoLocator`
  - selection spec
  - display metadata
  - stable `repo_id`

**Deliverables**

- new request structs in orchestrator/control-plane crate
- normalization pipeline:
  - canonicalize paths
  - validate repos exist / are Git repos
  - sort and dedupe
  - reject conflicting duplicates for MVP
  - sort and dedupe explicit refs

**Acceptance**

- same request content always normalizes to same ordered target list
- duplicate repo entries collapse deterministically
- conflicting duplicate entries fail loudly
- explicit refs normalize order-independently

**Pattern**

Static inventory normalization before shard registration.

---

### Ticket 4 — Define Git shard payload and metadata packing for repo-frontier shards

**Scope**

Create the typed shard payload for Git work.

**Decision**

For MVP, shard payload should carry exactly one normalized repo target plus its selection and execution settings. Do not create a shared multi-target manifest yet.

**Deliverables**

- `GitShardPayload`
- deterministic encode/decode (single fixed wire format, no version discriminants)
- redacted `Debug`
- payload validation on decode
- metadata mapping into `connector_extra` / shard metadata

**Acceptance**

- payload round-trips deterministically
- malformed payloads fail before execution
- no raw locator paths or refs appear in logs
- shard payload decode does not require external control-plane lookup

**Performance note**

Single-target payloads minimize worker startup complexity and keep execution O(1) for payload hydration.

---

### Ticket 5 — Implement the Git control-plane planner and run setup path

**Scope**

Mirror the filesystem control-plane pattern for Git.

**Decision**

Follow the same four-step structure already used for filesystem:

- request normalize
- initial shard plan
- payload encode
- `create_run(...)` + `register_shards(...)`

**Deliverables**

In `gossip-orchestrator` or equivalent:

- `git_request.rs`
- `git_planner.rs`
- `git_payload.rs`
- `git_setup.rs`

Planner behavior:

- one repo target -> one shard
- repo list -> one shard per target
- no pre-splitting

**Acceptance**

- submission creates active run + Git shards in etcd
- shard metadata is replay-safe
- duplicate submission handling is explicit
- planner output is deterministic for same request

**Pattern**

Create-run + register-shards control plane, reusing existing coordinator semantics.

---

### Ticket 6 — Implement explicit commit lowering via stable synthetic refs

**Scope**

Handle `single repo + explicit commit` safely and deterministically.

**Decision**

Lower explicit commit requests to synthetic refs in the managed mirror namespace, for example under a versioned private prefix such as:

- `refs/gossip/scan-targets/v1/commits/<oid>`

The executor then runs an explicit-ref selection, not a special commit-only execution path.

**Deliverables**

- synthetic ref naming rule
- mirror-side ref creation/update helper
- mapping from explicit commit request -> explicit ref selection
- missing-commit validation

**Acceptance**

- same commit request always maps to same synthetic ref name
- different commits map to different synthetic refs
- rerun is idempotent
- source repo is never mutated
- missing commit is classified as fatal input error

**Why this is the right shape**

It preserves stable ref naming for watermark semantics and avoids inventing a second execution mode.

---

### Ticket 7 — Implement deterministic local mirror management

**Scope**

Build the `GitMirrorManager` for local/static inputs.

**Decision**

Use a shared worker-local mirror cache rooted at configured mirror storage. Mirror path should be digest-based, not raw-path-based, to keep path lengths bounded and avoid leaking repo paths via filesystem names.

Recommended layout:

- `<mirror_root>/v1/local/<digest-prefix>/<digest>.git`

Mirror creation/update semantics:

- first use: create mirror in temp dir, then atomic rename
- later use: fetch/prune into existing mirror
- private synthetic refs live only in mirror namespace

**Deliverables**

- mirror path derivation
- first-create flow
- update/fetch flow
- lock protocol for concurrent updates
- retry classification

**Acceptance**

- repeated syncs reuse same mirror path
- interrupted first create does not leave authoritative partial mirror
- concurrent update attempts do not overlap unsafely
- lock contention is retryable
- invalid repo path / non-repo path is fatal

**Alternative**

Use shared/hardlinked clone to save time/space.
**Tradeoff**: better disk efficiency, worse isolation and harder reasoning. I would not do that in MVP.

**Performance note**

Mirror reuse is the main performance lever in this epic. It avoids recloning and makes reruns/ref scans much cheaper.

---

### Ticket 8 — Implement a minimal `GitRepoDiscoverySource` for static targets

**Scope**

Wire repo-frontier paging into runtime without overbuilding discovery.

**Decision**

For MVP, implement a `SingleTargetGitRepoDiscoverySource` or `StaticGitRepoDiscoverySource` that emits the one target carried in shard payload and obeys the discovery contract:

- ordered by `RepoKey`
- shard membership enforced
- key-authoritative resume
- bounded pages
- token optional, never required for resume

**Deliverables**

- `discover_page(...)` implementation
- optional `choose_split_point(...)` returning `None` for MVP or a trivial midpoint hint
- page validator tests

**Acceptance**

- first page returns the target exactly once
- restart from last key does not re-emit incorrectly
- stale/missing token does not block resume
- out-of-range emission is impossible
- logs only contain digests/hashes

**Why this ticket exists even for one-target shards**

It keeps runtime aligned with repo-frontier contracts now, so later split work composes cleanly.

---

### Ticket 9 — Build the `scanner-git` execution adapter

**Scope**

Map normalized Git shard work into `scanner-git::run_git_scan(...)`.

**Decision**

The adapter should:

- map `GitSelection` into `scanner-git` start-set config
- preserve stable ref names
- use the managed mirror path as repo root
- map runtime limits into Git execution limits
- classify `scanner-git` outcomes into retryable vs fatal

**Deliverables**

- adapter layer in `gossip-scanner-runtime`
- config mapper
- explicit-ref path
- explicit-commit-lowered path
- error mapper

**Acceptance**

- default-branch scan works
- explicit refs scan works
- explicit commit scan works through synthetic ref lowering
- retryable conditions are not marked fatal
- invalid refs / invalid commit selection are fatal

**Important semantic requirement**

Do not break inner watermark / seen-store semantics. The adapter must preserve the inner contract rather than flatten it.

---

### Ticket 10 — Implement inner Git persistence adapters and a repo-family durable receipt

**Scope**

Connect `scanner-git` persistence interfaces to project persistence in a way the outer runtime can trust.

**Decision**

Recommended path:

- implement adapters for `scanner-git` persistence traits
- return a `RepoExecutionReceipt` only after inner finalize is durably committed
- outer checkpoint waits on that receipt

Do **not** fake this by advancing outer progress when `run_git_scan(...)` merely returned success before durable inner persistence is confirmed.

**Deliverables**

- `RefWatermarkStore` adapter
- `SeenBlobStore` adapter
- `PersistenceStore` adapter
- atomic finalize wiring
- repo-family durable receipt type
- explicit mapping from durable repo receipt -> outer checkpoint input

**Acceptance**

- no early ACK
- crash after partial inner work does not advance outer frontier
- retry is idempotent
- watermark updates do not become visible without matching durable inner finalize
- stale worker cannot make progress look authoritative

**Pattern**

Checkpoint after durable commit, not before. This is the same core rule already called out in the persistence outline.

**Performance note**

Keep inner finalize batched. Do not turn a repo execution into thousands of synchronous per-object outer commits.

---

### Ticket 11 — Add the repo-frontier distributed runtime loop

**Scope**

Create the actual worker execution path for Git shards.

**Decision**

Do this as a separate narrow runtime path, not as a broad generalization of the current filesystem loop.

Recommended flow:

1. claim shard lease
2. decode Git payload
3. instantiate static discovery source
4. sync mirror
5. lower explicit commit if needed
6. execute `scanner-git`
7. wait for durable repo receipt
8. emit completed repo-frontier unit
9. checkpoint outer frontier
10. mark shard complete

**Deliverables**

- `run_git_repo_lease(...)` or equivalent
- lease-renew stop rules
- checkpoint integration
- shard completion path
- retry handling

**Acceptance**

- worker can claim and execute Git shard end-to-end
- lease loss stops execution quickly
- outer checkpoint advances only after inner durable receipt
- replay after worker reassignment is safe
- one target per shard completes cleanly

**Safe-stop rule**

If lease renewal becomes uncertain, pause/abort quickly. Better pause than overlap. That matches the project contract and connector boundary guidance.

---

### Ticket 12 — Enable distributed Git in worker configuration and production composition

**Scope**

Make the worker able to run Git in distributed mode.

**Decision**

Add Git distributed mode explicitly rather than overloading the existing direct-scan Git path.

**Deliverables**

- config parsing updates
- mirror-root config
- Git source mode validation
- worker dispatch wiring
- startup validation messages

**Acceptance**

- `source=git` is accepted in distributed mode
- invalid combinations are rejected clearly
- local/direct Git path still works separately
- production worker boots against etcd + real persistence for Git

---

### Ticket 13 — Add Git-specific contract, property, and failure tests

**Scope**

Prove no-overlap/no-gap behavior at the repo-frontier level and prove mirror/executor replay safety.

**Tests**

Unit tests:

- `RepoKey` round-trip and ordering
- request normalization and dedupe
- shard payload codec
- synthetic ref naming stability
- retry classification

Property / simulation tests:

- resume from last key with token loss
- lease loss mid-execution
- retry after reassignment
- crash after inner durable finalize but before outer checkpoint
- crash before inner durable finalize
- equal-key repo-frontier checkpoint behavior if applicable

**Acceptance**

- all Git-specific conformance tests pass in CI
- crash/retry does not violate outer/inner separation
- no raw locator/ref/token leakage in logs during tests

**Why this matters**

The phase gates for the project explicitly call for property tests and simulation around no-overlap/no-gaps and crash/retry durability. Epic 3 should meet that bar for the Git family too.

---

### Ticket 14 — Add real-backend end-to-end launch proof for Git

**Scope**

Create the Git equivalent of the existing filesystem real-backend launch proof.

**Deliverables**

- test repo generator
- orchestrator submission test
- etcd shard existence assertions
- worker launch
- durable completion assertions

Test matrix:

- single repo, default selection
- single repo + explicit refs
- single repo + explicit commit
- explicit repo list

**Acceptance**

- submission creates run + shards in etcd
- worker claims shard and completes it
- durable state exists where expected
- rerun is replay-safe

---

### Ticket 15 — Add minimum Git observability and redaction hooks

**Scope**

Not full Epic 6, just the minimum needed to operate Git MVP safely.

**Decision**

Use low-cardinality stage metrics and hashed identifiers only. Do not emit raw repo paths, ref names, commit IDs, or secret-derived data in logs/traces/metrics. That follows the Phase VI guidance.

**Deliverables**

Metrics:

- repo shard claimed/completed
- mirror sync latency
- mirror retries by class
- Git executor latency
- durable repo receipt latency
- outer checkpoint latency
- lease-loss count

Logs:

- structured events with hashed repo key / mirror digest only

**Acceptance**

- no raw repo path / ref / secret material appears in telemetry
- operators can distinguish mirror issues, executor issues, and checkpoint issues
- stalled repo shards are visible

---

## Critical dependencies and execution order

Recommended order:

1. Ticket 1
2. Ticket 2
3. Ticket 3
4. Ticket 4
5. Ticket 5
6. Ticket 6 and Ticket 7 in parallel
7. Ticket 8
8. Ticket 10
9. Ticket 11
10. Ticket 12
11. Ticket 13
12. Ticket 14
13. Ticket 15

The true critical path is:

- freeze the durable receipt seam,
- freeze `RepoKey` and normalized request shape,
- implement mirror management,
- implement `scanner-git` persistence adapter,
- wire the repo-frontier runtime.

## Invariants to keep explicit in every ticket

These should appear in ticket descriptions and test plans:

- a stale fence token must never be accepted again
- loss of lease must stop repo execution quickly
- outer repo frontier must never advance before inner durable persistence completes
- control-plane state must scale with shards, not objects inside repos
- same request inputs must normalize to the same ordered repo targets
- same explicit commit input must lower to the same synthetic ref
- no raw secret bytes, repo paths, refs, or tokens in logs/metrics/traces
- duplicate submission and worker replay must be idempotent

## The one design choice to settle first

The most important first decision is Ticket 10.

If the team gets the durable-receipt seam wrong, you will either:

- accidentally checkpoint outer repo progress before inner Git state is durable, or
- contort `scanner-git` into the ordered-content committer and spend the epic fighting the abstraction.

Everything else is straightforward once that seam is explicit.

The Epic 3 scope in the project outline is already the right size; the key is to keep the MVP shape narrow and resist adding provider discovery, multi-target shard packing, or repo-internal outer coordination state before the local/static path is solid.
