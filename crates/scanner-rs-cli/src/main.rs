//! scanner-rs CLI binary.
//!
//! Process-exit policy is intentionally handled in this binary while
//! `gossip-scanner-runtime` returns typed errors.

fn main() {
    match gossip_scanner_runtime::cli::parse_args() {
        Ok(config) => {
            if let Err(error) = gossip_scanner_runtime::cli::run(config) {
                eprintln!("{error}");
                std::process::exit(2);
            }
        }
        Err(gossip_scanner_runtime::cli::CliError::HelpRequested(usage)) => {
            println!("{usage}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}
