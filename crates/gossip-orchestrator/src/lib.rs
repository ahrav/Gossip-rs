//! Reusable control-plane surfaces for request normalization and planning.
//!
//! This crate owns the filesystem submission contract that later
//! orchestration steps consume for initial shard planning, payload encoding,
//! and run setup.

pub mod request;

pub use request::{
    FilesystemInitialPlanInput, FilesystemPathKind, FilesystemRequest, FilesystemRequestError,
    FilesystemSourceMode, NormalizedFilesystemRequest, NormalizedFilesystemSource,
};
