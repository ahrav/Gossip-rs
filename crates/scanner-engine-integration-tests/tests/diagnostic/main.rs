//! Diagnostic and analysis tools (most #[ignore] by default).
//!
//! Run with: `cargo test --features diagnostic-tests --test diagnostic -- --ignored --nocapture`

mod analyze_unfilterable;
mod print_unfilterable;
// alloc_after_startup requires #[global_allocator] and scheduler scan_local — deferred.
// mod alloc_after_startup;
