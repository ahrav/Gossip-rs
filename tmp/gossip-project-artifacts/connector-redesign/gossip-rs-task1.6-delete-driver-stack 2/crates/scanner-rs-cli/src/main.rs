//! scanner-rs CLI binary.
//!
//! Process-exit policy is intentionally handled in this binary while
//! `gossip-scanner-runtime` returns typed errors.

fn main() {
    match gossip_scanner_runtime::cli::parse_args() {
        Ok(config) => {
            if let Err(error) = gossip_scanner_runtime::cli::run(config) {
                print_error_chain(&error);
                std::process::exit(2);
            }
        }
        Err(gossip_scanner_runtime::cli::CliError::HelpRequested(usage)) => {
            println!("{usage}");
        }
        Err(error) => {
            print_error_chain(&error);
            std::process::exit(2);
        }
    }
}

/// Print the top-level error and the full causal chain to stderr.
///
/// Without this, nested errors (e.g. anyhow contexts wrapping typed errors)
/// display only the outermost message, hiding the actual root cause.
fn print_error_chain(error: &dyn std::error::Error) {
    eprintln!("error: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}
