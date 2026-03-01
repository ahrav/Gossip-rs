# Scanner Core Parity Fixtures

This document tracks the phase-1 parity gate for migrated scanner core logic in
`crates/gossip-engine`.

## What Is Canonicalized

`gossip_engine::canonicalize_stream_output` reduces `StreamScanOutput` into a
fixture-stable shape:

- `page_summaries` in stream order (`page_num`, `signature`, `item_count`, `bytes_scanned`)
- `findings` in emission order (`stable_item_id`, version strength/value,
  `page_num`, `item_index`, `fingerprint`, `payload_bytes`)

Keeping findings ordered means fixture checks fail on **ordering drift** and
identity drift.

## Fixture Location

- `crates/gossip-engine/tests/fixtures/phase1b_core_parity.json`

The integration test
`crates/gossip-engine/tests/fixture_parity.rs::migrated_core_matches_known_good_fixture`
is the hard gate.

## Throughput Policy Helper

`gossip_engine::enforce_throughput_thresholds` encodes the migration policy
used by later cutover phases:

- median absolute throughput delta <= `2.0%`
- per-case absolute throughput delta <= `5.0%`

`gossip_engine::throughput_delta_pct` and `gossip_engine::median` are companion
utilities used by the same gate.

## Runtime Integration Status

Phase-2/3 runtime wiring now consumes `gossip-engine` directly in both
standalone and worker paths:

- `crates/gossip-scanner-runtime` provides typed `scan_fs_direct` and
  `scan_git_direct` orchestration entrypoints.
- `crates/scanner-rs-cli` exposes the workspace `scanner-rs` binary with
  `scan fs|git` shape and `--execution-mode` defaulting to `direct`.
- `crates/gossip-worker` page processing uses `ScannerCore` through
  `run_scan_loop_with_page_processor`, replacing placeholder page-signature
  hashing as the functional scan path.

These paths intentionally keep connector mode explicit/gated until later
phases complete durable runtime backends and parity gates.

## Refresh Workflow

1. Run fixture test in print mode:
   `GOSSIP_ENGINE_PRINT_PARITY_FIXTURE=1 cargo test -p gossip-engine --test fixture_parity migrated_core_matches_known_good_fixture -- --nocapture`
2. If behavior change is intentional, update the JSON fixture.
3. Re-run:
   `cargo test -p gossip-engine --test fixture_parity`
