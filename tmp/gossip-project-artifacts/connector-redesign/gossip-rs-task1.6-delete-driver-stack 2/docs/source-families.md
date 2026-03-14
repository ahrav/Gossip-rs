# Source family guide

This repository no longer uses the old driver-stack source abstraction.

## Current source-family model

Use one of these families when adding new source work:

- `OrderedContentSource`
  - bounded ordered page fill of `ScanItem`
  - `open(...)`
  - optional `read_range(...)`
- `GitRepoDiscoverySource`
  - bounded ordered page fill of `GitRepoTarget`
- `GitMirrorManager`
  - deterministic local bare/mirror sync for Git repo work
- `GitRepoExecutor`
  - repo-native execution through `scanner-git`

## Migration rule

Do not reintroduce the removed driver-stack vocabulary or the old universal
source model. New source work must attach to one of the source families above.

## Guardrail

Two checks enforce this:

- `scripts/check_no_legacy_source_design.py`
- `crates/gossip-contracts/tests/no_legacy_source_design.rs`

Both fail if the removed identifiers are reintroduced in code or Cargo files.

## Practical guidance

- If the source pages content items and exposes bytes, it belongs in
  `OrderedContentSource`.
- If the source discovers repos for `scanner-git`, it belongs in
  `GitRepoDiscoverySource`.
- If the source needs to make a local Git mirror usable, it belongs in
  `GitMirrorManager`.
- If the source runs repo-native Git scanning, it belongs in
  `GitRepoExecutor`.
