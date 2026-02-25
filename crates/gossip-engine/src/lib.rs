//! Detection engine: rule matching via regex, vectorscan, and custom detectors.
//!
//! This crate owns the core detection logic that evaluates byte content
//! against a compiled rule set. It supports multiple matching backends:
//!
//! - **Regex** — Rust `regex` crate for portable pattern matching.
//! - **Vectorscan** — Intel Hyperscan / Vectorscan for high-throughput
//!   multi-pattern scanning on supported platforms.
//! - **Custom detectors** — application-specific matching logic that
//!   cannot be expressed as regular expressions (e.g., entropy checks,
//!   structured format validators).
//!
//! The engine is invoked by the scan pipeline (`gossip-scan-pipeline`) on
//! CPU-bound executor threads. It receives pre-chunked byte slices and
//! returns match results without performing I/O.
