# Scanner Core Parity

This document tracks the parity gate for scanner core logic consolidated into
`crates/scanner-engine`.

## Runtime Integration Status

The unified execution model (v5.4) routes all scanning through a single path:

- `crates/gossip-scanner-runtime` provides typed `scan_fs` and `scan_git`
  orchestration entrypoints backed by `ScanDriver`.
- `crates/scanner-rs-cli` exposes the workspace `scanner-rs` binary with
  `scan fs|git` shape and `--execution-mode` defaulting to `direct`.
- `crates/gossip-scan-driver` defines the `ScanDriver` and `ScanSourceFactory`
  traits that both CLI and distributed modes use.
- `crates/scanner-engine` owns the detection pipeline: vectorscan prefilter,
  regex, transform decode, offline validation, and finding emission.

Both CLI and distributed modes use the same `scanner-engine::Engine` instance
for detection. The difference between modes is only where work comes from
(CLI args vs coordinator) and where results go (JSONL vs distributed
persistence).

## Throughput Policy

Migration cutover is gated by sustained parity and performance thresholds:

- median absolute throughput delta <= `2.0%`
- per-case absolute throughput delta <= `5.0%`

## Historical Note

The former `gossip-engine` crate provided a Phase 1 migration scaffold with
deterministic page signatures, finding fingerprints, and fixture-based parity
comparison (`canonicalize_stream_output`, `enforce_throughput_thresholds`).
This was superseded by the v5.4 unified execution model which routes all
scanning through `scanner-engine` directly.
