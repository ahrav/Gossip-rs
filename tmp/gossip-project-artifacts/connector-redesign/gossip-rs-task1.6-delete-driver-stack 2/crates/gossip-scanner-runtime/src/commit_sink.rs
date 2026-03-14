//! Placeholder commit-sink module.
//!
//! The legacy scan-driver commit sink is intentionally no longer part of the
//! runtime compile surface. Durable commit gating will be rebuilt around the
//! new family-oriented runtime loops in later tasks.

/// Compatibility no-op retained temporarily for CLI/wiring stability.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CliNoOpCommitSink;

/// Placeholder durable commit sink type.
#[derive(Debug, Default)]
pub struct DurableCommitSink;
