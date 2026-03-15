# Scanner Core Parity

This document tracks the parity gate for scanner core logic consolidated into
`crates/scanner-engine`.

## Runtime Integration Status

The runtime-facing integration surface currently keeps configuration,
summary, and parity plumbing local to `gossip-scanner-runtime`:

- `crates/gossip-scanner-runtime` provides typed `scan_fs` and `scan_git`
  entrypoints plus sink-aware `scan_fs_with_runtime` and
  `scan_git_with_runtime` helpers.
- `crates/scanner-rs-cli` exposes the workspace `scanner-rs` binary with
  `scan fs|git` shape and `--execution-mode` defaulting to `direct`.
- `crates/gossip-worker` exercises the same runtime surface with a minimal
  worker-specific CLI.
- `crates/gossip-scanner-runtime` owns local `ScanReport`,
  `ScanCheckpoint`, `CancellationToken`, and commit-sink types.
- `crates/scanner-engine` owns the detection pipeline: vectorscan prefilter,
  regex, transform decode, offline validation, and finding emission.

At the moment the runtime validates scan inputs and preserves these typed
surfaces, then routes execution to family placeholders. End-to-end engine
execution parity is therefore scoped to the pieces that still run today:

- CLI parsing and summary rendering
- event-sink formatting
- JSONL canonicalization in `parity.rs`
- durable identity derivation in the local commit sink

When the family runtime loops land, the same public runtime API can resume
full detection-path parity work without another caller-facing surface change.

## Throughput Policy

Throughput gates apply to runtime paths that execute the scanner engine:

- median absolute throughput delta <= `2.0%`
- per-case absolute throughput delta <= `5.0%`
