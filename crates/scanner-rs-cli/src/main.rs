//! Unified Secret Scanner CLI
//!
//! This binary delegates entirely to the scanner-rs engine from
//! `scratch-scanner-rs`, providing identical behavior, findings, and
//! performance to the standalone `scanner-rs` binary.
//!
//! Routes to filesystem or git scanning via subcommands:
//!
//! ```text
//! scanner-rs scan fs --path <dir|file> [OPTIONS]
//! scanner-rs scan git --repo <path>    [OPTIONS]
//! ```
//!
//! See `scanner-rs scan fs --help` or `scanner-rs scan git --help` for
//! source-specific options.
//!
//! # Exit Codes
//!
//! - `0`: Success (regardless of findings count)
//! - `2`: Invalid arguments or scan error

use std::io;

fn main() -> io::Result<()> {
    let config = scanner_rs_lib::unified::cli::parse_args()?;
    scanner_rs_lib::unified::orchestrator::run(config)
}
