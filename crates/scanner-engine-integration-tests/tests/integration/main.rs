//! Integration tests migrated from scanner-rs.
//!
//! Run with: `cargo test --features integration-tests --test integration`

#[path = "../support/git_test_support.rs"]
mod git_test_support;

mod anchor_optimization;
mod archive_scanning;
mod bench_guards;
mod binary_awareness;
mod finding_json;
// execution_mode_parity requires invoking the scanner-rs binary from the integration target.
// mod execution_mode_parity;
// fs_cli_archives requires invoking the scanner-rs binary from the integration target.
// mod fs_cli_archives;
mod git_commit_walk;
mod git_engine_adapter;
mod git_inmem_artifacts;
mod git_mapping_bridge;
mod git_pack_differential;
mod git_pack_exec;
mod git_pack_inflate;
mod git_pack_inflate_corpus;
mod git_pack_plan;
mod git_persist;
mod git_preflight;
mod git_repo_open;
mod git_run_format;
mod git_scan_validation;
mod git_seen_crash_recovery;
mod git_seen_unique;
mod git_snapshot;
mod git_tree_diff;
mod manual_anchors;
// sqlite_persistence requires store::db module — not yet migrated.
// mod sqlite_persistence;
