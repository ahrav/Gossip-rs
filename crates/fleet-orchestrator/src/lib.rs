//! Fleet orchestrator library.
//!
//! Parallel documentation build and audit orchestration. Supports multiple
//! pipelines (guide-sync and design-doc-audit) that share common
//! infrastructure: Jetty API communication, git merge operations, PR
//! lifecycle management, fleet state tracking, and configuration.

pub mod affected;
pub mod audit;
pub mod config;
pub mod graph;
pub mod jetty;
pub mod merge;
pub mod partitioner;
pub mod pr;
pub mod state;
