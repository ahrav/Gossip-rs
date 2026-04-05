//! Fleet orchestrator library.
//!
//! Dependency-aware parallel documentation build orchestration for guide-sync.
//! Each module handles one concern of the pipeline: graph construction,
//! affected-chapter analysis, fleet state tracking, work partitioning,
//! Jetty API communication, git merge operations, PR lifecycle, and
//! configuration.

pub mod affected;
pub mod config;
pub mod graph;
pub mod jetty;
pub mod merge;
pub mod partitioner;
pub mod pr;
pub mod state;
