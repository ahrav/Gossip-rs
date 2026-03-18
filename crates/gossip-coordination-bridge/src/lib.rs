//! Coordination-to-runtime adapters for distributed scanner execution.
//!
//! This crate bridges production coordination backends into the
//! `gossip-scanner-runtime` distributed worker loop without creating a
//! dependency cycle between the coordination and runtime crates.

#![forbid(unsafe_code)]

mod adapter;
mod assignment;

pub use adapter::EtcdRuntimeAdapter;
pub use assignment::FilesystemAssignment;
