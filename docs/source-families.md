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
     Ok(None)          => terminal completion (shard fully enumerated)
     Ok(Some(PageBuf)) => { items, state: HasMore{cursor} | Complete }
     for each item:
        open(item_ref, budgets) -> Result<Box<dyn io::Read + Send>, ReadError>
        (optionally) read_range(item_ref, offset, dst, budgets) -> Result<usize, ReadError>
     checkpoint cursor
```

**Concrete connectors:**
`FilesystemConnector` directly implements `OrderedContentSource` and keeps
matching inherent helper methods in `gossip-connectors/src/filesystem.rs`.
`GitConnector` (git-tracked files via `ls-files`) and
`InMemoryDeterministicConnector` expose the same read/split surface as
inherent methods in `gossip-connectors/src/`.

**Submission staging (filesystem-specific):**

`gossip-orchestrator` stages filesystem submissions before runtime execution:
- `request.rs` canonicalizes raw paths, validates them against the requested
  source mode (single file vs. directory root), and enforces path/mode
  consistency. Produces `NormalizedFilesystemRequest`.
- `planner.rs` maps normalized requests into the deterministic one-shard
  startup geometry consumed by later payload and registration stages.

These stages are optional for other ordered-content sources (e.g., git
ls-files connectors) but required for filesystem security and determinism.

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
| `crates/gossip-contracts/src/connector/mod.rs` | Re-export hub, canonical connector tags |
| `crates/gossip-connectors/src/filesystem.rs` | Filesystem ordered-content connector |
| `crates/gossip-connectors/src/git.rs` | Git `ls-files` ordered-content connector |
| `crates/gossip-connectors/src/in_memory.rs` | Deterministic in-memory test connector |
| `crates/gossip-connectors/src/common.rs` | Shared connector utilities |
| `crates/gossip-connectors/src/split_estimator.rs` | Streaming byte-weighted split-point estimator (internal; used by `common.rs` and `FilesystemConnector`) |
| `crates/gossip-orchestrator/src/lib.rs` | Re-export hub for filesystem request normalization and planning |
| `crates/gossip-orchestrator/src/request.rs` | Canonical filesystem submission request normalization |
| `crates/gossip-orchestrator/src/planner.rs` | Deterministic filesystem initial shard geometry planner |
| `crates/gossip-scanner-runtime/src/ordered_content.rs` | Runtime integration for ordered content |
| `crates/gossip-scanner-runtime/src/git_repo.rs` | Runtime integration for Git repo-native |
| `crates/gossip-scanner-runtime/src/commit_pipeline.rs` | Family-neutral bounded execution -> durable-commit bridge shared after result translation |
| `crates/gossip-scanner-runtime/src/commit_sink.rs` | Commit-sink trait and bridge record types for scan-loop lifecycle |
| `crates/gossip-scanner-runtime/src/commit_model.rs` | Frozen runtime commit vocabulary: `CompletedUnit`, `CommitRequest`, `UnitCommitReceipt` |
| `crates/gossip-scanner-runtime/src/result_translation.rs` | Deterministic scan-result -> persistence-row translation |
| `crates/gossip-scanner-runtime/src/result_committer.rs` | Authoritative findings -> done-ledger durable commit stage |
| `crates/gossip-scanner-runtime/src/checkpoint_aggregator.rs` | Receipt-driven prefix checkpoint aggregation |
| `crates/gossip-scanner-runtime/src/coordination_sink.rs` | Coordination event recorder payloads for distributed scans |
| `crates/gossip-scanner-runtime/src/distributed.rs` | Distributed worker-loop runtime and receipt-backed commit plumbing |

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
