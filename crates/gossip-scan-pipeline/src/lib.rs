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
//!
//! Design trade-offs:
//! - The loop is synchronous and deterministic; retry pacing/backoff is not handled
//!   internally.
//! - Retry behavior is intentionally bounded and caller-configured via
//!   `max_transient_retries`.
//! - Chunking and detection-engine fan-out are out of scope in this crate revision.

mod scan_loop;

pub use scan_loop::{DEFAULT_MAX_TRANSIENT_RETRIES, ScanLoopError, ScanLoopOutcome, run_scan_loop};
