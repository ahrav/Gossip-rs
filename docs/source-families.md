# Source-Family Model

## Overview

Source integration is organized by **family**: each family defines its own
trait surface tuned to the semantics of that source category. Families compose
from a shared paging and value vocabulary (`PageBuf`, `Cursor`, `ItemKey`,
`Budgets`, error types in `gossip-contracts/src/connector/`) but have
independent trait surfaces. Once a family runtime finishes executing one work
unit, it can hand that unit to the shared runtime commit pipeline to make
durable progress through a family-neutral path.

---

## Families

### Ordered Content

Item-at-a-time enumeration and byte reads. The coordination layer assigns
shard ranges; the runtime drives the source through page-fill / scan / read
cycles.

| Trait | Crate | File | Role |
|-------|-------|------|------|
| `OrderedContentSource` | `gossip-contracts` | `src/connector/ordered.rs` | Fill pages of `ScanItem`, open/read item bytes |

**Key types:** `OrderedContentCapabilities`, `ScanItem`, `PageBuf<ScanItem>`,
`Cursor`, `Budgets`, `EnumerateError`, `ReadError`.

**Worker loop sketch:**

```text
fill_page(shard, cursor, budgets)
  -> Result<Option<PageBuf<ScanItem>>, EnumerateError>
     Ok(None)          => exhausted-empty terminal signal
     Ok(Some(PageBuf)) => { items, state: HasMore{cursor} | Complete }
                          Complete pages are terminal non-empty pages; the
                          runtime performs one exhausted-empty suffix call
                          before treating the shard as fully enumerated.
     for each item:
        open(item_ref, budgets) -> Result<Box<dyn io::Read + Send>, ReadError>
        (optionally) read_range(item_ref, offset, dst, budgets) -> Result<usize, ReadError>
     checkpoint cursor
```

**Concrete connectors:**
`FilesystemConnector` directly implements `OrderedContentSource` and keeps
matching inherent helper methods in `gossip-connectors/src/filesystem.rs`.
`InMemoryDeterministicConnector` exposes the same read/split surface as
inherent methods in `gossip-connectors/src/in_memory.rs`.

**Submission staging:**

`gossip-orchestrator` stages filesystem submissions before runtime execution:
- `request.rs` canonicalizes raw paths, validates them against the requested
  source mode (single file vs. directory root), and enforces path/mode
  consistency. For untrusted input, `normalize_within(allowed_root)` also
  verifies that the canonical path resides within a server-configured root
  directory, rejecting symlink escapes and traversal attempts. Produces
  `NormalizedFilesystemRequest`.
- `planner.rs` maps normalized requests into the deterministic one-shard
  startup geometry consumed by later payload and registration stages.
- `payload.rs` encodes the typed filesystem shard metadata that coordination
  stores in `connector_extra` and the runtime later decodes during lease
  hydration.
- `setup.rs` lowers the normalized request, planned geometry, and typed
  payload into a validated initial manifest, then executes the
  `create_run_with_shards` lifecycle that makes the startup shard set
  claimable.
- `git_request.rs` canonicalizes raw Git repo targets, validates repository
  identity via tenant-scoped normalization, and preserves request-side
  selection intent (default-branch, explicit refs, or explicit commit) for
  later Git control-plane stages.
- `git_payload.rs` encodes the typed Git shard metadata that coordination
  stores in `connector_extra` for repo-frontier shards and the runtime later
  decodes during Git lease hydration.

The filesystem stages are required for filesystem security and determinism.
Git request normalization is required for tenant-scoped identity resolution
and target deduplication.

### Git Repo-Native

Whole-repository operations: commit walks, tree diffs, pack scans. Git
execution is intentionally separate from ordered-content because the runtime
operates on entire repositories rather than individual items.

| Trait | Crate | File | Role |
|-------|-------|------|------|
| `GitRepoDiscoverySource` | `gossip-contracts` | `src/connector/git.rs` | Page over `GitRepoTarget` in `RepoKey` order |
| `GitMirrorManager` | `gossip-contracts` | `src/connector/git.rs` | Acquire or refresh a `LocalMirror` |
| `GitRepoExecutor` | `gossip-contracts` | `src/connector/git.rs` | Run repo-native scanning against a mirror |

**Key types:** `RepoKey`, `RepoLocator`, `GitRepoTarget`, `GitSelection`,
`LocalMirror`, `GitExecutionLimits`, `GitRunOutcome`, `GitRunError`,
`GitDiscoveryCapabilities`.

**Pipeline:**

```text
1. GitRepoDiscoverySource::discover_page(shard, cursor, budgets)
   -> Result<Option<PageBuf<GitRepoTarget>>, EnumerateError>
      Ok(None) => terminal completion (shard fully enumerated)
2. GitMirrorManager::sync_mirror(locator)
   -> Result<LocalMirror, GitRunError>
3. GitRepoExecutor::run_repo(mirror, selection, limits)
   -> Result<GitRunOutcome, GitRunError>
```

`gossip-scanner-runtime/src/git_discovery.rs` defines the payload-backed
`StaticGitRepoDiscoverySource` for one-target repo-frontier shards. It
emits one terminal page when the carried `RepoKey` is inside the assigned shard
and otherwise relies on the ordered key boundary for replay-safe completion.
`gossip-scanner-runtime/src/git_repo.rs` wires that source into
`GitRepoRuntime::execute_discovery`, which the distributed runtime uses before
and after repo execution to decide whether a singleton shard is already covered
by its cursor or is complete after a durable finalize-backed checkpoint.
`gossip-scanner-runtime/src/git_persistence.rs` defines the runtime-owned
adapter that satisfies `scanner-git`'s ref-watermark, seen-blob, and finalize
persistence seams and maps complete inner finalizes onto the shared
repo-frontier receipt/checkpoint path. `run_git_repo_worker` in
`gossip-scanner-runtime/src/distributed.rs` composes the full singleton path:
static discovery, mirror sync, mirror-backed execution through
`GitRepoRuntime::execute_repo`, capture of emitted finding payloads through
`FindingsCaptureSink`, translation via the shared
`PersistenceFinding`/`translate_git_item_result` path, and finally shard
advancement from the durable repo-frontier checkpoint cursor.

---

## Shared Paging Vocabulary

All families build on types in `gossip-contracts/src/connector/common.rs`:

| Type | Role |
|------|------|
| `PageBuf<T>` | Non-empty page container with `PageState` (HasMore / Complete) |
| `PageState` | Cursor-carrying continuation or terminal signal |
| `PagingCapabilities` | Feature flags: `ordered_keys`, `resumable`, `splittable` |
| `KeyedPageItem` | Trait: `item_key()` + `size_hint()` |
| `validate_filled_page` | Validates non-empty, strictly increasing keys within shard bounds |

Error types (`EnumerateError`, `ReadError`) and value types (`ItemKey`,
`ItemRef`, `Cursor`, `Budgets`) live in `gossip-contracts/src/connector/api.rs`
and `types.rs`.

---

## Source file inventory

| File | Purpose |
|------|---------|
| `crates/gossip-contracts/src/connector/ordered.rs` | Ordered-content family contract |
| `crates/gossip-contracts/src/connector/git.rs` | Git family contract (three traits + supporting types) |
| `crates/gossip-contracts/src/connector/common.rs` | Shared paging vocabulary |
| `crates/gossip-contracts/src/connector/types.rs` | Toxic-byte wrappers, cursor, budgets |
| `crates/gossip-contracts/src/connector/api.rs` | Error taxonomy, capabilities |
| `crates/gossip-contracts/src/connector/conformance.rs` | Ordered-content conformance harness shared by concrete connector implementations |
| `crates/gossip-contracts/src/connector/mod.rs` | Re-export hub, canonical connector tags |
| `crates/gossip-contracts/src/connector/api_tests.rs` | Unit tests for error taxonomy and capabilities |
| `crates/gossip-contracts/src/connector/common_tests.rs` | Unit tests for shared paging vocabulary |
| `crates/gossip-contracts/src/connector/types_tests.rs` | Unit tests for toxic-byte wrappers, cursor, and budgets |
| `crates/gossip-connectors/src/lib.rs` | Crate root re-exports for concrete filesystem and in-memory connector implementations |
| `crates/gossip-connectors/src/filesystem.rs` | Filesystem ordered-content connector |
| `crates/gossip-connectors/src/in_memory.rs` | Deterministic in-memory test connector |
| `crates/gossip-connectors/src/common.rs` | Shared connector utilities |
| `crates/gossip-connectors/src/split_estimator.rs` | Streaming byte-weighted split-point estimator (internal; used by `common.rs` and `FilesystemConnector`) |
| `crates/gossip-connectors/src/filesystem_tests.rs` | Unit tests for filesystem connector |
| `crates/gossip-connectors/src/in_memory_tests.rs` | Unit tests for in-memory connector |
| `crates/gossip-connectors/src/split_estimator_tests.rs` | Unit tests for split-point estimator |
| `crates/gossip-orchestrator/src/lib.rs` | Re-export hub for filesystem and Git request normalization, planning, and run setup |
| `crates/gossip-orchestrator/src/git_payload.rs` | Typed Git shard payload wire format for repo-frontier shards (encode/decode) |
| `crates/gossip-orchestrator/src/git_planner.rs` | Deterministic Git initial shard geometry planner |
| `crates/gossip-orchestrator/src/git_request.rs` | Canonical Git submission request normalization and target deduplication |
| `crates/gossip-orchestrator/src/git_setup.rs` | Coordination-backed Git run setup and shard registration |
| `crates/gossip-orchestrator/src/request.rs` | Canonical filesystem submission request normalization |
| `crates/gossip-orchestrator/src/planner.rs` | Deterministic filesystem initial shard geometry planner |
| `crates/gossip-orchestrator/src/payload.rs` | Typed filesystem shard payload wire format (encode/decode) |
| `crates/gossip-orchestrator/src/setup.rs` | Coordination-backed filesystem run setup and shard registration |
| `crates/gossip-orchestrator/src/test_support.rs` | Shared test fixtures for orchestrator unit tests |
| `crates/gossip-scanner-runtime/src/lib.rs` | Runtime crate root: public family entrypoints, execution-mode selection, validation, and shared scan report/config types |
| `crates/gossip-scanner-runtime/src/cli.rs` | CLI/runtime flag mapping and entrypoint wiring for filesystem and Git scans |
| `crates/gossip-scanner-runtime/src/ordered_content.rs` | Runtime integration for ordered content |
| `crates/gossip-scanner-runtime/src/git_discovery.rs` | Static single-target Git repository discovery source |
| `crates/gossip-scanner-runtime/src/git_executor.rs` | Contract-level adapter that runs scanner-git against a local mirror |
| `crates/gossip-scanner-runtime/src/git_persistence.rs` | Runtime-backed Git persistence adapters and repo-frontier receipt helpers |
| `crates/gossip-scanner-runtime/src/git_mirror.rs` | Worker-local Git mirror lifecycle and deterministic mirror-cache naming |
| `crates/gossip-scanner-runtime/src/git_repo.rs` | Runtime integration for Git repo-native |
| `crates/gossip-scanner-runtime/src/commit_pipeline.rs` | Family-neutral bounded execution -> durable-commit bridge shared after result translation |
| `crates/gossip-scanner-runtime/src/commit_sink.rs` | Commit-sink trait and bridge record types for scan-loop lifecycle |
| `crates/gossip-scanner-runtime/src/commit_model.rs` | Frozen runtime commit vocabulary: `CompletedUnit`, `CommitRequest`, `UnitCommitReceipt` |
| `crates/gossip-scanner-runtime/src/done_ledger_bloom.rs` | In-memory Bloom filter used to prefilter done-ledger lookups during durable commit processing |
| `crates/gossip-scanner-runtime/src/event_sink.rs` | Owned event sinks and forwarders for CLI/runtime output surfaces |
| `crates/gossip-scanner-runtime/src/parity.rs` | Cross-scanner parity helpers shared by runtime tests and tooling |
| `crates/gossip-scanner-runtime/src/result_translation.rs` | Deterministic scan-result -> persistence-row translation |
| `crates/gossip-scanner-runtime/src/result_committer.rs` | Authoritative findings -> done-ledger durable commit stage |
| `crates/gossip-scanner-runtime/src/checkpoint_aggregator.rs` | Receipt-driven prefix checkpoint aggregation |
| `crates/gossip-scanner-runtime/src/coordination_sink.rs` | Coordination event recorder payloads for distributed scans |
| `crates/gossip-scanner-runtime/src/distributed.rs` | Distributed worker-loop runtime and receipt-backed commit plumbing |
| `crates/gossip-scanner-runtime/src/cli_tests.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/distributed/commit_bridge.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/distributed/execution.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/distributed/integration_tests.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/distributed/lease_ops.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/distributed/test_support.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/distributed/types.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/distributed/unit_tests.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/lib_tests.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/runtime_durability_tests.rs` | [Undocumented] |
| `crates/gossip-scanner-runtime/src/test_fixtures.rs` | [Undocumented] |

---

## Adding a New Source Family

1. **Define the contract** in `gossip-contracts/src/connector/` — one or more
   traits plus any family-specific value types. Build on the shared paging
   vocabulary where applicable.
2. **Implement** in `gossip-connectors/src/` — concrete connector(s) for the
   family.
3. **Wire into runtime** in `gossip-scanner-runtime/src/` — translation from
   coordination shard assignments to the family's trait surface.
4. **Update this doc** — add the new family to the table above.

See [boundary-4-connectors.md](gossip-connectors/boundary-4-connectors.md)
for the full connector architecture including paging invariants, error
taxonomy, and the ordered-content conformance harness.
