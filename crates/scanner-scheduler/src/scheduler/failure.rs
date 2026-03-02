//! Failure Model & Retry Budget System
//!
//! # Design
//!
//! This module defines the contract between scheduler and backends for:
//! - Error classification (retry decisions)
//! - Retry budgets (per-object time + attempt limits)
//! - Partial results policy (surface findings from failed objects?)
//! - Observable retry state (for metrics/debugging)
//!
//! # Error Classification Hierarchy
//!
//! ```text
//! BackendError
//! â”œâ”€â”€ Retryable
//! â”‚   â”œâ”€â”€ Timeout         - Network/read timeout, definitely retry
//! â”‚   â”œâ”€â”€ RateLimit       - 429, respect Retry-After header
//! â”‚   â”œâ”€â”€ ServerError     - 500/502/503/504, transient backend issue
//! â"‚   â"œâ"€â"€ ConnectionReset - Network blip, retry immediately
//! â"‚   â""â"€â"€ TransientIo     - Disk busy, interrupted, etc.
//! â""â"€â"€ Permanent
//!     â"œâ"€â"€ NotFound        - 404, object deleted during scan
//!     â"œâ"€â"€ AccessDenied    - 403, auth/permission issue
//!     â"œâ"€â"€ InvalidResponse - Malformed data, can't parse
//!     â"œâ"€â"€ Cancelled       - User-initiated cancellation
//!     â"œâ"€â"€ TooLarge        - Object exceeds configured size limit
//!     â""â"€â"€ Unsupported     - Unsupported object type (symlink, device, etc.)
//! ```
//!
//! # Retry Budget Scope
//!
//! **Important**: A `RetryBudget` tracks all attempts for a single *object*,
//! not per-fetch or per-chunk. The budget should be created when object
//! processing begins and shared across all chunk fetches for that object.
//!
//! ```text
//! Object "foo.txt" (3 chunks)
//! â””â”€â”€ RetryBudget (shared across all chunks)
//!     â”œâ”€â”€ Chunk 0: attempt 1 (success)
//!     â”œâ”€â”€ Chunk 1: attempt 2 (timeout), attempt 3 (success)  
//!     â””â”€â”€ Chunk 2: attempt 4 (success)
//!     Total: 4 attempts, 1 retry
//! ```
//!
//! # Retry Budget Invariants
//!
//! - **Bounded attempts**: Never retry more than `max_attempts`
//! - **Bounded time**: Total object processing time capped by `max_duration`
//! - **Retry-After respected**: Server's rate limit directive is authoritative
//! - **Budget independence**: Each object gets fresh budget (no global state)

use std::time::{Duration, Instant};

// ============================================================================
// Error Classification
// ============================================================================

/// Fine-grained retryable error subtypes.
///
/// These guide retry strategy (immediate vs delayed, backoff multiplier).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryableReason {
    /// Network/read timeout. Retry with normal backoff.
    Timeout,
    /// Rate limited (HTTP 429). May have Retry-After hint.
    RateLimit {
        /// Suggested wait time from Retry-After header, if present.
        retry_after: Option<Duration>,
    },
    /// Server error (5xx). Retry with backoff.
    ServerError,
    /// Connection reset/dropped. Retry immediately (no backoff).
    ConnectionReset,
    /// Transient I/O error (disk busy, etc). Retry with backoff.
    TransientIo,
}

/// Fine-grained permanent error subtypes.
///
/// These determine logging level and whether to continue the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermanentReason {
    /// Object not found (404). Normal for deleted files during scan.
    NotFound,
    /// Access denied (403). Auth/permission issue.
    AccessDenied,
    /// Invalid/malformed response. Backend bug or corruption.
    InvalidResponse,
    /// User-initiated cancellation. Not logged as error.
    Cancelled,
    /// Object size exceeds configured limit.
    TooLarge,
    /// Unsupported object type (e.g., symlink, device file).
    Unsupported,
}

/// Classification of backend errors for retry decisions.
///
/// Extends the simple Retryable/Permanent binary with rich subtypes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient error - worth retrying
    Retryable(RetryableReason),
    /// Permanent error - don't retry
    Permanent(PermanentReason),
}

impl ErrorClass {
    /// Quick check for retryable errors.
    #[inline]
    pub fn is_retryable(&self) -> bool {
        matches!(self, ErrorClass::Retryable(_))
    }

    /// Quick check for permanent errors.
    #[inline]
    pub fn is_permanent(&self) -> bool {
        matches!(self, ErrorClass::Permanent(_))
    }

    /// Check if this is a "normal" failure (not worth warning about).
    ///
    /// NotFound during scan is normal (file deleted between list and fetch).
    /// Cancelled is user-initiated, not an error.
    #[inline]
    pub fn is_expected(&self) -> bool {
        matches!(
            self,
            ErrorClass::Permanent(PermanentReason::NotFound)
                | ErrorClass::Permanent(PermanentReason::Cancelled)
        )
    }

    /// Check if this is user-initiated cancellation.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, ErrorClass::Permanent(PermanentReason::Cancelled))
    }
}

// ============================================================================
// Retry Policy
// ============================================================================

/// Configuration for retry behavior per backend.
///
/// # Defaults
///
/// ```text
/// max_attempts: 4 (1 initial + 3 retries)
/// base_delay: 50ms
/// max_delay: 2s (for computed backoff only, NOT for Retry-After)
/// jitter_pct: 20%
/// ```
///
/// # Retry-After Behavior
///
/// The `max_delay` cap applies only to computed exponential backoff.
/// Server-provided `Retry-After` headers are **authoritative** and will
/// NOT be capped by `max_delay`. If `Retry-After` exceeds your time budget,
/// the budget will be exhausted rather than violating the server directive.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Maximum attempts per object (including initial attempt).
    /// Invariant: >= 1
    pub max_attempts: u32,

    /// Base delay before first retry.
    pub base_delay: Duration,

    /// Maximum delay between retries (caps exponential growth).
    /// NOTE: Does NOT cap server-provided Retry-After values.
    pub max_delay: Duration,

    /// Jitter as percentage of computed delay (0-100).
    /// Jitter helps avoid thundering herd when multiple fetches fail.
    pub jitter_pct: u8,

    /// Multiplier for rate-limit (429) Retry-After values.
    /// Applied to server hint before comparison.
    /// Must be finite and >= 0.
    pub rate_limit_multiplier: f32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
            jitter_pct: 20,
            rate_limit_multiplier: 1.0,
        }
    }
}

impl RetryPolicy {
    /// Create a policy that never retries.
    pub const fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            jitter_pct: 0,
            rate_limit_multiplier: 1.0,
        }
    }

    /// Create an aggressive retry policy for flaky backends.
    pub fn aggressive() -> Self {
        Self {
            max_attempts: 6,
            base_delay: Duration::from_millis(25),
            max_delay: Duration::from_secs(5),
            jitter_pct: 30,
            rate_limit_multiplier: 1.5,
        }
    }

    /// Validate policy invariants.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn validate(&self) {
        assert!(self.max_attempts >= 1, "max_attempts must be >= 1");
        assert!(self.jitter_pct <= 100, "jitter_pct must be <= 100");
        assert!(
            self.rate_limit_multiplier >= 0.0 && self.rate_limit_multiplier.is_finite(),
            "rate_limit_multiplier must be finite and >= 0"
        );
    }
}

// ============================================================================
// Retry Budget (Per-Object)
// ============================================================================

/// Per-object retry budget tracker.
///
/// # Scope
///
/// A single `RetryBudget` tracks ALL attempts for one object across all
/// its chunk fetches. Create one budget per object, not per fetch.
///
/// # Timing
///
/// The duration budget starts on the first `record_attempt()` call, not
/// on construction. This ensures queue wait time doesn't count against
/// the processing budget.
///
/// # Usage
///
/// ```ignore
/// let mut budget = RetryBudget::new(policy, Some(Duration::from_secs(30)));
///
/// // For each chunk fetch in this object:
/// loop {
///     budget.record_attempt();
///     match backend.fetch_range(obj, offset, buf) {
///         Ok(n) => break Ok(n),
///         Err(e) => {
///             let class = backend.classify_error(&e);
///             match budget.should_retry(class, rng.next_u64()) {
///                 RetryDecision::Retry { reason, delay } => {
///                     std::thread::sleep(delay);
///                     continue;
///                 }
///                 RetryDecision::Exhausted(reason) => break Err((e, reason)),
///             }
///         }
///     }
/// }
/// ```
///
/// # No Clone
///
/// Intentionally does not implement `Clone` to prevent accidental
/// state duplication. Create fresh budgets for new objects.
#[derive(Debug)]
pub struct RetryBudget {
    policy: RetryPolicy,

    /// Maximum total time for this object (None = no limit).
    max_duration: Option<Duration>,

    /// When execution started (set on first record_attempt).
    /// None until first attempt - queue time doesn't count.
    started: Option<Instant>,

    /// Number of attempts made (including initial).
    attempts: u32,

    /// Number of retries granted (times `should_retry` returned `Retry`).
    retries: u32,

    /// Total retry time spent sleeping.
    retry_time: Duration,

    /// Last retry reason (for debugging/metrics).
    last_reason: Option<RetryableReason>,

    /// Debug: track state machine (attempt recorded before should_retry)
    #[cfg(debug_assertions)]
    attempt_pending: bool,
}

/// Decision from retry budget check.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RetryDecision {
    /// Should retry after this delay.
    Retry {
        /// Why we're retrying.
        reason: RetryableReason,
        /// How long to wait before retry.
        delay: Duration,
    },
    /// Budget exhausted, give up.
    Exhausted(ExhaustionReason),
}

/// Why the retry budget was exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExhaustionReason {
    /// Hit max_attempts limit
    MaxAttempts,
    /// Hit max_duration limit
    MaxDuration,
    /// Error was not retryable
    PermanentError,
    /// Rate limit Retry-After exceeds remaining time budget
    RateLimitExceedsBudget,
}

impl RetryBudget {
    /// Create a new retry budget for an object.
    ///
    /// The duration timer does NOT start until `record_attempt()` is called.
    pub fn new(policy: RetryPolicy, max_duration: Option<Duration>) -> Self {
        policy.validate();
        Self {
            policy,
            max_duration,
            started: None, // Lazy init on first attempt
            attempts: 0,
            retries: 0,
            retry_time: Duration::ZERO,
            last_reason: None,
            #[cfg(debug_assertions)]
            attempt_pending: false,
        }
    }

    /// Record that an attempt is starting.
    ///
    /// Call this BEFORE each fetch attempt. Starts the duration timer
    /// on first call.
    #[inline]
    pub fn record_attempt(&mut self) {
        // Start timer on first attempt (not on construction)
        if self.started.is_none() {
            self.started = Some(Instant::now());
        }

        self.attempts = self.attempts.saturating_add(1);

        #[cfg(debug_assertions)]
        {
            self.attempt_pending = true;
        }
    }

    /// Check if we should retry given the error classification.
    ///
    /// Returns `Retry { reason, delay }` if retry is allowed, or `Exhausted(reason)`.
    ///
    /// # Panics (debug only)
    ///
    /// Debug builds panic if `record_attempt()` was not called before this.
    pub fn should_retry(&mut self, class: ErrorClass, rng_u64: u64) -> RetryDecision {
        #[cfg(debug_assertions)]
        {
            debug_assert!(
                self.attempt_pending,
                "must call record_attempt() before should_retry()"
            );
            self.attempt_pending = false;
        }

        // Check if error is retryable
        let reason = match class {
            ErrorClass::Permanent(_) => {
                return RetryDecision::Exhausted(ExhaustionReason::PermanentError);
            }
            ErrorClass::Retryable(r) => r,
        };

        // Check attempt limit
        if self.attempts >= self.policy.max_attempts {
            return RetryDecision::Exhausted(ExhaustionReason::MaxAttempts);
        }

        // Compute delay
        let delay = self.compute_delay(reason, rng_u64);

        // Check time budget
        if let Some(max) = self.max_duration {
            let elapsed = self.elapsed();
            if elapsed + delay > max {
                // Special case: rate limit with explicit Retry-After that exceeds budget
                if matches!(
                    reason,
                    RetryableReason::RateLimit {
                        retry_after: Some(_)
                    }
                ) {
                    return RetryDecision::Exhausted(ExhaustionReason::RateLimitExceedsBudget);
                }
                return RetryDecision::Exhausted(ExhaustionReason::MaxDuration);
            }
        }

        // Record retry stats
        self.retries = self.retries.saturating_add(1);
        self.retry_time = self.retry_time.saturating_add(delay);
        self.last_reason = Some(reason);

        RetryDecision::Retry { reason, delay }
    }

    /// Compute backoff delay for the current attempt.
    fn compute_delay(&self, reason: RetryableReason, rng_u64: u64) -> Duration {
        // Special case: ConnectionReset gets immediate retry (no delay) on early attempts
        if matches!(reason, RetryableReason::ConnectionReset) && self.attempts <= 2 {
            return Duration::ZERO;
        }

        // Exponential backoff: base * 2^(attempt-1)
        let exp = self.attempts.saturating_sub(1).min(30);
        let mut delay = self.policy.base_delay.saturating_mul(1u32 << exp);

        // Cap computed delay at max_delay
        if delay > self.policy.max_delay {
            delay = self.policy.max_delay;
        }

        // Handle rate limit with explicit Retry-After
        // CRITICAL: Server's Retry-After is AUTHORITATIVE - do NOT cap by max_delay
        if let RetryableReason::RateLimit {
            retry_after: Some(hint),
        } = reason
        {
            let multiplier = self.policy.rate_limit_multiplier as f64;
            let scaled_secs = hint.as_secs_f64() * multiplier;

            // Clamp to reasonable range to avoid Duration overflow
            let clamped_secs = scaled_secs.clamp(0.0, 86400.0); // Max 24 hours
            let scaled = Duration::from_secs_f64(clamped_secs);

            // Server directive wins - no max_delay cap here
            if scaled > delay {
                delay = scaled;
            }
        }

        // Apply jitter to computed delay
        self.apply_jitter(delay, rng_u64)
    }

    /// Apply jitter to delay using provided random bits.
    ///
    /// Uses uniform distribution in `[delay - jitter%, delay + jitter%]` rather than
    /// exponential or truncated normal. Uniform is simpler and sufficient for
    /// decorrelating retry storms across workers.
    fn apply_jitter(&self, delay: Duration, rng_u64: u64) -> Duration {
        let jitter_pct = self.policy.jitter_pct as u64;
        if jitter_pct == 0 || delay.is_zero() {
            return delay;
        }

        let delay_ns = delay.as_nanos() as u64;
        let jitter_ns = delay_ns.saturating_mul(jitter_pct) / 100;

        if jitter_ns == 0 {
            return delay;
        }

        // Uniform in [delay - jitter, delay + jitter]
        let span = jitter_ns.saturating_mul(2);
        let r = rng_u64 % (span.saturating_add(1));

        // Calculate offset: r is in [0, span], we want [-jitter, +jitter]
        if r < jitter_ns {
            // Negative offset
            let offset = jitter_ns - r;
            Duration::from_nanos(delay_ns.saturating_sub(offset))
        } else {
            // Positive offset
            let offset = r - jitter_ns;
            Duration::from_nanos(delay_ns.saturating_add(offset))
        }
    }

    /// Get number of attempts made.
    #[inline]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Get number of retries (successful should_retry calls).
    #[inline]
    pub fn retries(&self) -> u32 {
        self.retries
    }

    /// Get total time spent in retry delays.
    #[inline]
    pub fn retry_time(&self) -> Duration {
        self.retry_time
    }

    /// Get elapsed time since first attempt.
    ///
    /// Returns `Duration::ZERO` if no attempts have been made.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.started.map(|s| s.elapsed()).unwrap_or(Duration::ZERO)
    }

    /// Get last retry reason (for debugging).
    #[inline]
    pub fn last_reason(&self) -> Option<RetryableReason> {
        self.last_reason
    }

    /// Check if any retries occurred.
    #[inline]
    pub fn had_retries(&self) -> bool {
        self.retries > 0
    }
}

// ============================================================================
// Partial Results Policy
// ============================================================================

/// Policy for handling findings from partially-scanned objects.
///
/// When an object fails mid-scan (some chunks succeeded, some failed):
///
/// # Note on Streaming
///
/// This policy applies at finalize time when using buffered collection.
/// If you implement streaming output (emit findings as they're found),
/// `DiscardAll` cannot retract already-emitted findings. In that case,
/// use `KeepPartial` and attach a terminal status record per object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PartialResultsPolicy {
    /// Discard all findings from this object.
    /// Use when completeness is required (compliance scans).
    /// Only works with buffered output (findings held until object completes).
    #[default]
    DiscardAll,

    /// Keep findings from completed chunks, mark object as partial.
    /// Use when some findings are better than none (triage scans).
    KeepPartial,
}

// ============================================================================
// Observable Failure State
// ============================================================================

/// Summary of failure state for an object (for metrics/reporting).
#[derive(Clone, Debug, Default)]
pub struct FailureSummary {
    /// Total attempts made
    pub attempts: u32,
    /// Number of retries
    pub retries: u32,
    /// Total time spent in retry delays
    pub retry_delay_total: Duration,
    /// Final outcome
    pub outcome: ObjectOutcome,
    /// Final error class if failed (None for success)
    pub final_error: Option<ErrorClass>,
}

/// Final outcome for an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ObjectOutcome {
    /// Not yet complete
    #[default]
    InProgress,
    /// Completed successfully
    Success,
    /// Failed after exhausting retries
    FailedRetryExhausted,
    /// Failed due to permanent error
    FailedPermanent,
    /// Partially completed (some chunks succeeded)
    Partial,
    /// Cancelled before completion (user-initiated, not an error)
    Cancelled,
}

impl FailureSummary {
    /// Create summary from a completed retry budget.
    pub fn from_budget(
        budget: &RetryBudget,
        outcome: ObjectOutcome,
        final_error: Option<ErrorClass>,
    ) -> Self {
        Self {
            attempts: budget.attempts,
            retries: budget.retries,
            retry_delay_total: budget.retry_time,
            outcome,
            final_error,
        }
    }

    /// Check if this represents a terminal failure (`FailedRetryExhausted` or
    /// `FailedPermanent`). Returns `false` for success, cancellation,
    /// in-progress, and partial outcomes.
    pub fn is_error(&self) -> bool {
        matches!(
            self.outcome,
            ObjectOutcome::FailedRetryExhausted | ObjectOutcome::FailedPermanent
        )
    }

    /// Check if this was user-initiated cancellation.
    pub fn is_cancelled(&self) -> bool {
        self.outcome == ObjectOutcome::Cancelled
    }
}

// ============================================================================
// Backend Error Adapter
// ============================================================================

/// Adapter trait for converting backend-specific errors to ErrorClass.
///
/// Backends implement this to map their native error types to the
/// scheduler's error classification system.
pub trait ClassifyError {
    /// The backend's native error type.
    type Error;

    /// Classify a backend error for retry decisions.
    fn classify(&self, error: &Self::Error) -> ErrorClass;
}

// ============================================================================
// Predefined Error Classifiers
// ============================================================================

/// HTTP status code classifier (for REST API backends).
pub struct HttpStatusClassifier;

impl HttpStatusClassifier {
    /// Classify an HTTP status code.
    ///
    /// # Status Code Handling
    ///
    /// | Code | Classification |
    /// |------|----------------|
    /// | 408 | Retryable::Timeout (server-side request timeout) |
    /// | 413 | Permanent::TooLarge (payload too large) |
    /// | 429 | Retryable::RateLimit (with Retry-After) |
    /// | 5xx | Retryable::ServerError |
    /// | 404/410 | Permanent::NotFound |
    /// | 401/403 | Permanent::AccessDenied |
    /// | Other 4xx | Permanent::InvalidResponse |
    pub fn classify_status(status: u16, retry_after: Option<Duration>) -> ErrorClass {
        match status {
            200..=299 => unreachable!("success codes shouldn't be classified as errors"),

            // Timeouts - retryable
            408 => ErrorClass::Retryable(RetryableReason::Timeout),

            // Rate limiting
            429 => ErrorClass::Retryable(RetryableReason::RateLimit { retry_after }),

            // Server errors - retryable
            500 | 502 | 503 | 504 => ErrorClass::Retryable(RetryableReason::ServerError),

            // Payload too large - permanent
            413 => ErrorClass::Permanent(PermanentReason::TooLarge),

            // Range not satisfiable - permanent (object changed or client bug)
            416 => ErrorClass::Permanent(PermanentReason::InvalidResponse),

            // Client errors - permanent
            401 | 403 => ErrorClass::Permanent(PermanentReason::AccessDenied),
            404 | 410 => ErrorClass::Permanent(PermanentReason::NotFound),

            // Other 4xx - permanent (includes 400)
            400..=499 => ErrorClass::Permanent(PermanentReason::InvalidResponse),

            // Other 5xx - retryable
            500..=599 => ErrorClass::Retryable(RetryableReason::ServerError),

            // Unknown - treat as permanent
            _ => ErrorClass::Permanent(PermanentReason::InvalidResponse),
        }
    }
}

/// I/O error classifier (for filesystem/local backends).
pub struct IoErrorClassifier;

impl IoErrorClassifier {
    /// Classify a std::io::ErrorKind.
    pub fn classify_io_error(kind: std::io::ErrorKind) -> ErrorClass {
        use std::io::ErrorKind::*;

        match kind {
            // Retryable I/O errors
            TimedOut => ErrorClass::Retryable(RetryableReason::Timeout),
            WouldBlock => ErrorClass::Retryable(RetryableReason::TransientIo),
            ConnectionReset | ConnectionAborted | BrokenPipe => {
                ErrorClass::Retryable(RetryableReason::ConnectionReset)
            }
            Interrupted => ErrorClass::Retryable(RetryableReason::TransientIo),

            // Permanent I/O errors
            NotFound => ErrorClass::Permanent(PermanentReason::NotFound),
            PermissionDenied => ErrorClass::Permanent(PermanentReason::AccessDenied),
            InvalidData | InvalidInput => ErrorClass::Permanent(PermanentReason::InvalidResponse),

            // Unsupported operations
            Unsupported => ErrorClass::Permanent(PermanentReason::Unsupported),

            // Default: treat as retryable transient I/O
            _ => ErrorClass::Retryable(RetryableReason::TransientIo),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_class_queries() {
        let retryable = ErrorClass::Retryable(RetryableReason::Timeout);
        assert!(retryable.is_retryable());
        assert!(!retryable.is_permanent());
        assert!(!retryable.is_expected());

        let not_found = ErrorClass::Permanent(PermanentReason::NotFound);
        assert!(!not_found.is_retryable());
        assert!(not_found.is_permanent());
        assert!(not_found.is_expected()); // NotFound is expected during scans

        let access_denied = ErrorClass::Permanent(PermanentReason::AccessDenied);
        assert!(!access_denied.is_expected()); // AccessDenied is NOT expected

        let cancelled = ErrorClass::Permanent(PermanentReason::Cancelled);
        assert!(cancelled.is_expected());
        assert!(cancelled.is_cancelled());
    }

    #[test]
    fn retry_policy_validation() {
        let policy = RetryPolicy::default();
        policy.validate(); // Should not panic

        let no_retry = RetryPolicy::no_retry();
        no_retry.validate();
    }

    #[test]
    #[should_panic(expected = "max_attempts must be >= 1")]
    fn retry_policy_zero_attempts_panics() {
        let policy = RetryPolicy {
            max_attempts: 0,
            ..Default::default()
        };
        policy.validate();
    }

    #[test]
    #[should_panic(expected = "rate_limit_multiplier must be finite")]
    fn retry_policy_infinite_multiplier_panics() {
        let policy = RetryPolicy {
            rate_limit_multiplier: f32::INFINITY,
            ..Default::default()
        };
        policy.validate();
    }

    #[test]
    fn retry_budget_exhausts_attempts() {
        let policy = RetryPolicy {
            max_attempts: 3,
            ..RetryPolicy::default()
        };
        let mut budget = RetryBudget::new(policy, None);

        // First attempt
        budget.record_attempt();
        let decision = budget.should_retry(ErrorClass::Retryable(RetryableReason::Timeout), 12345);
        assert!(matches!(decision, RetryDecision::Retry { .. }));

        // Second attempt
        budget.record_attempt();
        let decision = budget.should_retry(ErrorClass::Retryable(RetryableReason::Timeout), 12346);
        assert!(matches!(decision, RetryDecision::Retry { .. }));

        // Third attempt (at limit)
        budget.record_attempt();
        let decision = budget.should_retry(ErrorClass::Retryable(RetryableReason::Timeout), 12347);
        assert_eq!(
            decision,
            RetryDecision::Exhausted(ExhaustionReason::MaxAttempts)
        );
    }

    #[test]
    fn retry_budget_rejects_permanent() {
        let policy = RetryPolicy::default();
        let mut budget = RetryBudget::new(policy, None);

        budget.record_attempt();
        let decision = budget.should_retry(ErrorClass::Permanent(PermanentReason::NotFound), 12345);
        assert_eq!(
            decision,
            RetryDecision::Exhausted(ExhaustionReason::PermanentError)
        );
    }

    #[test]
    fn retry_budget_respects_duration_limit() {
        let policy = RetryPolicy {
            base_delay: Duration::from_secs(10), // Very long delay
            ..RetryPolicy::default()
        };
        let mut budget = RetryBudget::new(policy, Some(Duration::from_millis(100)));

        budget.record_attempt();
        let decision = budget.should_retry(ErrorClass::Retryable(RetryableReason::Timeout), 12345);
        // Delay would exceed duration limit
        assert_eq!(
            decision,
            RetryDecision::Exhausted(ExhaustionReason::MaxDuration)
        );
    }

    #[test]
    fn retry_budget_connection_reset_immediate() {
        let policy = RetryPolicy::default();
        let mut budget = RetryBudget::new(policy, None);

        budget.record_attempt();
        let decision = budget.should_retry(
            ErrorClass::Retryable(RetryableReason::ConnectionReset),
            12345,
        );

        // ConnectionReset should have zero delay on early attempts
        match decision {
            RetryDecision::Retry { delay, .. } => {
                assert_eq!(delay, Duration::ZERO);
            }
            _ => panic!("expected Retry decision"),
        }
    }

    #[test]
    fn retry_budget_rate_limit_respects_header_uncapped() {
        // CRITICAL: Retry-After must NOT be capped by max_delay
        let policy = RetryPolicy {
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2), // Much smaller than hint
            rate_limit_multiplier: 1.0,
            jitter_pct: 0, // No jitter for deterministic test
            ..RetryPolicy::default()
        };
        let mut budget = RetryBudget::new(policy, None);

        budget.record_attempt();
        let decision = budget.should_retry(
            ErrorClass::Retryable(RetryableReason::RateLimit {
                retry_after: Some(Duration::from_secs(60)), // Server says 60s
            }),
            12345,
        );

        match decision {
            RetryDecision::Retry { delay, .. } => {
                // Must be 60s, NOT capped at 2s
                assert_eq!(delay, Duration::from_secs(60));
            }
            _ => panic!("expected Retry decision"),
        }
    }

    #[test]
    fn retry_budget_rate_limit_exceeds_time_budget() {
        let policy = RetryPolicy {
            rate_limit_multiplier: 1.0,
            jitter_pct: 0,
            ..RetryPolicy::default()
        };
        // Only 10s budget
        let mut budget = RetryBudget::new(policy, Some(Duration::from_secs(10)));

        budget.record_attempt();
        let decision = budget.should_retry(
            ErrorClass::Retryable(RetryableReason::RateLimit {
                retry_after: Some(Duration::from_secs(60)), // Server says 60s
            }),
            12345,
        );

        // Should exhaust with specific reason, NOT hammer the server
        assert_eq!(
            decision,
            RetryDecision::Exhausted(ExhaustionReason::RateLimitExceedsBudget)
        );
    }

    #[test]
    fn retry_budget_tracks_retries() {
        let policy = RetryPolicy::default();
        let mut budget = RetryBudget::new(policy, None);

        budget.record_attempt();
        let decision = budget.should_retry(ErrorClass::Retryable(RetryableReason::Timeout), 12345);
        assert!(matches!(decision, RetryDecision::Retry { .. }));

        assert!(budget.had_retries());
        assert_eq!(budget.retries(), 1);
        assert_eq!(budget.last_reason(), Some(RetryableReason::Timeout));
    }

    #[test]
    fn retry_budget_lazy_timer_start() {
        let policy = RetryPolicy::default();
        let budget = RetryBudget::new(policy, Some(Duration::from_secs(30)));

        // Before any attempt, elapsed should be zero
        assert_eq!(budget.elapsed(), Duration::ZERO);

        // Create a new budget and record attempt
        let mut budget2 = RetryBudget::new(policy, Some(Duration::from_secs(30)));
        budget2.record_attempt();

        // Now elapsed should be non-zero (timer started)
        // Note: This could be flaky if exactly 0ns elapsed, but unlikely
        std::thread::sleep(Duration::from_millis(1));
        assert!(budget2.elapsed() >= Duration::from_millis(1));
    }

    #[test]
    fn retry_decision_carries_reason() {
        let policy = RetryPolicy::default();
        let mut budget = RetryBudget::new(policy, None);

        budget.record_attempt();
        let decision =
            budget.should_retry(ErrorClass::Retryable(RetryableReason::ServerError), 12345);

        match decision {
            RetryDecision::Retry { reason, delay: _ } => {
                assert_eq!(reason, RetryableReason::ServerError);
            }
            _ => panic!("expected Retry decision"),
        }
    }

    #[test]
    fn http_status_classifier() {
        // Server errors - retryable
        assert!(matches!(
            HttpStatusClassifier::classify_status(500, None),
            ErrorClass::Retryable(RetryableReason::ServerError)
        ));
        assert!(matches!(
            HttpStatusClassifier::classify_status(503, None),
            ErrorClass::Retryable(RetryableReason::ServerError)
        ));

        // Request timeout - retryable
        assert!(matches!(
            HttpStatusClassifier::classify_status(408, None),
            ErrorClass::Retryable(RetryableReason::Timeout)
        ));

        // Rate limit
        assert!(matches!(
            HttpStatusClassifier::classify_status(429, Some(Duration::from_secs(5))),
            ErrorClass::Retryable(RetryableReason::RateLimit {
                retry_after: Some(_)
            })
        ));

        // Payload too large - permanent
        assert!(matches!(
            HttpStatusClassifier::classify_status(413, None),
            ErrorClass::Permanent(PermanentReason::TooLarge)
        ));

        // Range not satisfiable - permanent
        assert!(matches!(
            HttpStatusClassifier::classify_status(416, None),
            ErrorClass::Permanent(PermanentReason::InvalidResponse)
        ));

        // Client errors - permanent
        assert!(matches!(
            HttpStatusClassifier::classify_status(404, None),
            ErrorClass::Permanent(PermanentReason::NotFound)
        ));
        assert!(matches!(
            HttpStatusClassifier::classify_status(403, None),
            ErrorClass::Permanent(PermanentReason::AccessDenied)
        ));
    }

    #[test]
    fn io_error_classifier() {
        use std::io::ErrorKind;

        // Retryable
        assert!(matches!(
            IoErrorClassifier::classify_io_error(ErrorKind::TimedOut),
            ErrorClass::Retryable(RetryableReason::Timeout)
        ));
        assert!(matches!(
            IoErrorClassifier::classify_io_error(ErrorKind::ConnectionReset),
            ErrorClass::Retryable(RetryableReason::ConnectionReset)
        ));
        assert!(matches!(
            IoErrorClassifier::classify_io_error(ErrorKind::WouldBlock),
            ErrorClass::Retryable(RetryableReason::TransientIo)
        ));

        // Permanent
        assert!(matches!(
            IoErrorClassifier::classify_io_error(ErrorKind::NotFound),
            ErrorClass::Permanent(PermanentReason::NotFound)
        ));
        assert!(matches!(
            IoErrorClassifier::classify_io_error(ErrorKind::PermissionDenied),
            ErrorClass::Permanent(PermanentReason::AccessDenied)
        ));
    }

    #[test]
    fn failure_summary_from_budget() {
        let policy = RetryPolicy::default();
        let mut budget = RetryBudget::new(policy, None);

        budget.record_attempt();
        let _ = budget.should_retry(ErrorClass::Retryable(RetryableReason::Timeout), 12345);
        budget.record_attempt();

        let summary = FailureSummary::from_budget(&budget, ObjectOutcome::Success, None);

        assert_eq!(summary.attempts, 2);
        assert_eq!(summary.retries, 1);
        assert_eq!(summary.outcome, ObjectOutcome::Success);
        assert!(!summary.is_error());
        assert!(!summary.is_cancelled());
    }

    #[test]
    fn failure_summary_cancelled_not_error() {
        let summary = FailureSummary {
            attempts: 1,
            retries: 0,
            retry_delay_total: Duration::ZERO,
            outcome: ObjectOutcome::Cancelled,
            final_error: Some(ErrorClass::Permanent(PermanentReason::Cancelled)),
        };

        assert!(!summary.is_error()); // Cancelled is NOT an error
        assert!(summary.is_cancelled());
    }

    #[test]
    fn partial_results_policy_default() {
        let policy = PartialResultsPolicy::default();
        assert_eq!(policy, PartialResultsPolicy::DiscardAll);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "must call record_attempt")]
    fn debug_panics_without_record_attempt() {
        let policy = RetryPolicy::default();
        let mut budget = RetryBudget::new(policy, None);

        // Skip record_attempt() - should panic in debug
        let _ = budget.should_retry(ErrorClass::Retryable(RetryableReason::Timeout), 12345);
    }
}
