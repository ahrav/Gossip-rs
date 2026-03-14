//! Property-based and exhaustive soundness tests migrated from scanner-rs.
//!
//! Run with: `cargo test --features property-tests --test property`

mod archive_entry_ratio;
mod archive_path_canonicalization;
mod archive_sliding_window;
mod binary_classification;
mod counterexample_determinism;
mod counterexample_family_soundness;
mod counterexample_shrinker;
mod entropy_threshold_soundness;
// git_commit_meta requires EventEncoder/JsonlEncoder — not yet migrated.
// mod git_commit_meta;
mod git_commit_walk;
mod git_engine_adapter;
mod git_pack_delta;
mod git_pack_plan;
mod git_spill_dedupe;
mod git_tree_diff;
mod path_policy_soundness;
mod regex2anchor_soundness;
mod secret_bytes_safelist_soundness;
mod value_suppressor_soundness;

mod proptest_support;
