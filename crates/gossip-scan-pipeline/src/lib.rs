//! Scan-pipeline runtime wiring for connector enumeration progress.
//!
//! Current scope:
//! 1. Run one acquired shard through `enumerate -> validate -> checkpoint/complete`.
//! 2. Convert connector failures into explicit coordination terminal actions.
//! 3. Keep operation IDs and logical time injected by callers for deterministic
//!    replay in simulation tests.
//!
//! Coordination invariants:
//! - A page is validated before any checkpoint/complete transition is attempted.
//! - An empty page is treated as terminal and completes the shard with the page's
//!   next cursor.
//! - Invalid shard or cursor bridging input is treated as poisoned state and is
//!   parked.
//! - Lease renewal is synchronous and checked between pages.
//! - `LeaseLost` is reserved for "abandon without terminal mutation" paths:
//!   deadline elapsed before checkpoint, or renewal failure after checkpoint.
//! - Once a coordination mutation is attempted (`checkpoint`/`complete`/`park`),
//!   backend failures (including lease-expired rejections) surface as `Error`.
//!
//! Design trade-offs:
//! - The loop is synchronous and deterministic; retry pacing/backoff is not handled
//!   internally.
//! - Retry behavior is intentionally bounded and caller-configured via
//!   `max_transient_retries`.
//! - Lease-renew timing is caller-configured via `RenewalPolicy` in
//!   `run_scan_loop_with_policy`; `run_scan_loop` uses half-life renewal.
//! - Reporting lease loss separately from mutation failures gives callers a clear
//!   split between "reacquire and continue from last checkpoint" and
//!   "coordination mutation failed; investigate backend error."
//! - Default behavior keeps chunking and detection-engine fan-out external.
//!   Hook-enabled APIs provide an explicit per-page processing injection point.

mod scan_loop;

pub use scan_loop::{
    DEFAULT_MAX_TRANSIENT_RETRIES, DEFAULT_RENEW_AT_FRACTION, LeaseLossCause,
    PageProcessingContext, PageProcessingError, RenewalPolicy, ScanLoopError, ScanLoopOutcome,
    run_scan_loop, run_scan_loop_with_page_processor, run_scan_loop_with_policy,
    run_scan_loop_with_policy_and_page_processor,
};
