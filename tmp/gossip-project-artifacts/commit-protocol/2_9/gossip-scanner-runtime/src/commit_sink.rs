//! Commit-sink compatibility shims for non-durable runtime entry points.
//!
//! The authoritative Epic 2 durability path is the receipt-driven execution →
//! commit pipeline (`ReceiptCommitSink` in `distributed.rs` feeding
//! `ResultCommitter`). This module intentionally keeps only the scan-driver
//! trait re-export plus the CLI no-op implementation used by local scans.
//!
//! Keeping the old `DurableCommitSink` out of the tree closes the main
//! compatibility side door: distributed durability must now flow through
//! findings → done-ledger → receipt → checkpoint, not through ad hoc
//! per-callback telemetry writes.

/// Re-export the scan-driver commit callback trait for legacy adapter code
/// that still names it through `crate::commit_sink::CommitSink`.
pub use gossip_scan_driver::CommitSink;
/// No-op commit sink used by CLI/local scans that do not persist findings.
pub use gossip_scan_driver::NoOpCommitSink as CliNoOpCommitSink;
