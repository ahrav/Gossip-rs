# Repository guard scripts

These scripts support repo-wide invariants that are easy to regress during
active refactors.

## Source-family migration guard

`check_no_legacy_source_design.py` fails if removed driver-stack identifiers
reappear in Rust source or Cargo manifests.

This guard exists so new work cannot quietly drift back to the removed source
model after Epic 1.
