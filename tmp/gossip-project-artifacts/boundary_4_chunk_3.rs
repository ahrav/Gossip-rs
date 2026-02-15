//! Boundary â‘£ â€” Connector Contract: Chunk 3 (DRAFT)
//!
//! Runtime bridge: validation helpers, cursor extraction, error mapping,
//! circuit breaker state, connector registration, and per-item outcomes.
//!
//! This file is additive to Boundaries â‘ â€“â‘¢ (all chunks) and Boundary â‘£
//! chunks 1â€“2 (value types, traits, errors).
//!
//! ## Problem Statement
//!
//! The enumeration and reading traits (chunk 2) define what connectors
//! produce. This chunk defines how the **runtime** consumes and validates
//! that output. The gap between "connector returned a page" and "runtime
//! checkpoints progress" requires:
//!
//! 1. **Page validation**: asserting all chunk-1/chunk-2 invariants
//!    (ordering, membership, identity consistency, budget compliance,
//!    liveness) in a single pass.
//!
//! 2. **Cursor extraction**: computing the checkpoint `Cursor` from an
//!    `EnumerationPage` â€” bridging B4 (connector output) to B2
//!    (coordinator input).
//!
//! 3. **Error mapping**: translating connector errors into coordination
//!    actions (retry, park with reason, skip item).
//!
//! 4. **Circuit breaker state**: tracking per-connector health to avoid
//!    hammering a failing source. Referenced in scanner instructions Â§4.5.
//!
//! 5. **Connector registration**: the handshake between a connector and
//!    the runtime at startup, validating tag uniqueness and capability.
//!
//! 6. **Item outcomes**: per-item terminal states for progress tracking
//!    and B5 done-ledger updates.
//!
//! ## Design Decisions (locked)
//!
//! D4.20: Page validation is a pure function of `(EnumerationPage, ShardSpec,
//!        EnumerationBudget)`. It does NOT call the coordinator or connector.
//!        This keeps validation testable and deterministic.
//!
//!        Reference: Separation of mechanism and policy â€” same philosophy
//!        as B3 chunk 5's `verify_coverage` operating on `&[ShardSummary]`.
//!
//! D4.21: Cursor extraction from a page is deterministic and infallible
//!        for a validated page. The runtime calls `extract_checkpoint_cursor`
//!        AFTER validation passes, so it can assume invariants hold.
//!
//! D4.22: Error-to-ParkReason mapping is a pure function. The runtime
//!        decides whether to actually park (based on retry count, circuit
//!        breaker state, etc.), but the mapping tells it WHICH reason
//!        to use IF it decides to park.
//!
//! D4.23: Circuit breaker state is a value type, NOT a controller. The
//!        runtime owns the state machine transitions. The contracts crate
//!        provides the state representation and transition conditions.
//!
//!        Reference: Nygard, *Release It!* (2018), Chapter 5 â€” circuit
//!        breaker pattern: Closed â†’ Open â†’ Half-Open.
//!
//! D4.24: Connector registration is a value type (`ConnectorRegistration`)
//!        that bundles `ConnectorInfo` with capability flags. The runtime
//!        validates uniqueness and stores the registration. The contracts
//!        crate does NOT manage a registry â€” that's runtime state.
//!
//!        Reference: FoundationDB's layered architecture â€” each layer
//!        registers capabilities; the binding layer validates compatibility.
//!
//! D4.25: ItemOutcome is a per-item terminal state, NOT an error type.
//!        It captures all possible outcomes including success. The runtime
//!        aggregates these for shard-level stats and done-ledger updates.

// ============================================================================
// Uses from prior boundaries and B4 chunks 1â€“2:
//
// B1:  CanonicalBytes, ConnectorTag, ItemKey, StableItemId
// B2:  Cursor, ShardSpec, ParkReason
// B4:  VersionId, ItemRef, ScanItem, ContentHints, ItemLocation,
//      EnumerationBudget, ReadBudget, EnumerationPage,
//      EnumerationError, ReadError, RetryHint, BudgetField,
//      ReadResult, ConnectorInfo, EnumerationConnector, ReadConnector
// ============================================================================

use core::fmt;

// ============================================================================
// Â§ Chunk 3: Runtime Bridge â€” Validation, Extraction, Mapping
// ============================================================================

// ---------------------------------------------------------------------------
// Â§3.1 PageValidation â€” comprehensive page invariant checking
// ---------------------------------------------------------------------------

/// Result of validating an `EnumerationPage` against its shard spec
/// and budget.
///
/// Aggregates all invariant violations found in a single pass. The
/// runtime should treat ANY violation as a serious bug â€” either in the
/// connector implementation or in the runtime's shard assignment logic.
///
/// ## Why Collect All Violations
///
/// We collect ALL violations rather than failing on the first one.
/// This aids debugging: if a connector is broken in multiple ways,
/// the operator sees the full picture in one log entry rather than
/// fixing issues one at a time.
///
/// Reference: Tiger Style â€” "provide as much diagnostic context as
/// possible on failure."
#[derive(Clone, Debug, Default)]
pub struct PageValidation {
    /// Item indices where `stable_item_id != item_key.stable_id()`.
    /// Violations of INV-4.S03.
    pub identity_mismatches: Vec<usize>,

    /// Adjacent item pairs (i, i+1) where item[i].key > item[i+1].key.
    /// Violations of INV-4.S04.
    pub ordering_violations: Vec<(usize, usize)>,

    /// Item indices whose `item_key.path` falls outside `[spec.start, spec.end)`.
    /// Violations of INV-4.S06.
    pub membership_violations: Vec<usize>,

    /// True if `page.items.len() > budget.max_items`.
    /// Violation of INV-4.S05.
    pub budget_exceeded: bool,

    /// True if `page.items.is_empty() && page.next_cursor.is_some()`.
    /// Empty page with continuation cursor and no error = liveness violation.
    /// Violation of INV-4.L01.
    pub liveness_violation: bool,
}

impl PageValidation {
    /// Returns `true` if no violations were found.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.identity_mismatches.is_empty()
            && self.ordering_violations.is_empty()
            && self.membership_violations.is_empty()
            && !self.budget_exceeded
            && !self.liveness_violation
    }

    /// Total number of individual violations found.
    pub fn violation_count(&self) -> usize {
        self.identity_mismatches.len()
            + self.ordering_violations.len()
            + self.membership_violations.len()
            + usize::from(self.budget_exceeded)
            + usize::from(self.liveness_violation)
    }
}

impl fmt::Display for PageValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_valid() {
            return write!(f, "page valid");
        }

        write!(f, "page validation FAILED:")?;

        if !self.identity_mismatches.is_empty() {
            write!(f, " identity_mismatches={:?}", self.identity_mismatches)?;
        }
        if !self.ordering_violations.is_empty() {
            write!(f, " ordering_violations={:?}", self.ordering_violations)?;
        }
        if !self.membership_violations.is_empty() {
            write!(f, " membership_violations={:?}", self.membership_violations)?;
        }
        if self.budget_exceeded {
            write!(f, " budget_exceeded=true")?;
        }
        if self.liveness_violation {
            write!(f, " liveness_violation=true")?;
        }
        Ok(())
    }
}

/// Validate an `EnumerationPage` against all connector contract invariants.
///
/// Single-pass O(N) check over all items, verifying:
///
/// 1. **Identity consistency** (INV-4.S03): `stable_item_id == item_key.stable_id()`
/// 2. **Ordering** (INV-4.S04): items in non-decreasing `(connector, path)` order
/// 3. **Membership** (INV-4.S06): all item keys within `[spec.start, spec.end)`
/// 4. **Budget compliance** (INV-4.S05): item count â‰¤ budget.max_items
/// 5. **Liveness** (INV-4.L01): empty page with Some(cursor) = violation
///
/// ## Pure Function
///
/// No I/O, no coordinator calls, no connector calls. Deterministic
/// given the same inputs.
///
/// Note: identity consistency requires one BLAKE3 hash per item
/// (for `stable_id()` recomputation).
pub fn validate_page(
    page: &EnumerationPage,
    spec: &ShardSpec,
    budget: &EnumerationBudget,
) -> PageValidation {
    let mut result = PageValidation::default();

    // INV-4.S05: budget compliance.
    if page.items.len() > budget.max_items as usize {
        result.budget_exceeded = true;
    }

    // INV-4.L01: liveness â€” empty page with continuation is suspicious.
    if page.items.is_empty() && page.next_cursor.is_some() {
        result.liveness_violation = true;
    }

    for (i, item) in page.items.iter().enumerate() {
        // INV-4.S03: identity consistency.
        if !item.check_identity_consistency() {
            result.identity_mismatches.push(i);
        }

        // INV-4.S04: ordering (compare with previous item).
        if i > 0 {
            let prev = &page.items[i - 1];
            let prev_key = (&prev.item_key.connector, &prev.item_key.path);
            let curr_key = (&item.item_key.connector, &item.item_key.path);
            if prev_key > curr_key {
                result.ordering_violations.push((i - 1, i));
            }
        }

        // INV-4.S06: membership â€” item_key.path within [spec.start, spec.end).
        if !check_key_membership(item.item_key.path.as_ref(), spec) {
            result.membership_violations.push(i);
        }
    }

    result
}

/// Check whether a key falls within a shard spec's `[start, end)` range.
///
/// Half-open interval: `start <= key < end`. Empty start = beginning of
/// keyspace (always satisfied). Empty end = unbounded (always satisfied).
///
/// Same semantics as `check_cursor_bounds` in B2 chunk 1 (D2.2), but
/// operates on raw key bytes rather than a `Cursor`.
///
/// Reference: Bigtable `[startRow, endRow)`, Spanner half-open tablets,
/// CockroachDB `[StartKey, EndKey)`, FoundationDB `[begin, end)`.
#[inline]
pub fn check_key_membership(key: &[u8], spec: &ShardSpec) -> bool {
    // Lower bound: start <= key. Empty start â†’ always satisfied.
    if !spec.key_range_start.is_empty() && key < spec.key_range_start.as_ref() {
        return false;
    }
    // Upper bound: key < end. Empty end â†’ always satisfied.
    if !spec.key_range_end.is_empty() && key >= spec.key_range_end.as_ref() {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Â§3.2 Cursor Extraction â€” bridging EnumerationPage to Cursor
// ---------------------------------------------------------------------------

/// Extract a checkpoint `Cursor` from a validated `EnumerationPage`.
///
/// Bridges B4 (connector output) to B2 (coordinator input). After the
/// runtime processes a page's items, it needs a `Cursor` to pass to
/// `coordinator.checkpoint()`.
///
/// ## Behavior
///
/// - `page.next_cursor` is `Some(c)` â†’ returns `Some(c)` (explicit
///   continuation, preserves opaque token for efficient resumption).
/// - `page.next_cursor` is `None` (last page) â†’ constructs cursor
///   from last item's key (final checkpoint before `complete()`).
/// - Empty page with no cursor â†’ returns `None` (no progress to checkpoint).
///
/// ## Precondition
///
/// The page MUST have passed `validate_page`. If called on an invalid
/// page, the cursor may be incorrect (ordering / membership not guaranteed).
///
/// ## Invariants
///
/// **Safety (monotonicity)**: The returned cursor's `last_key` is >=
/// the input cursor's `last_key` for a validated page. Guaranteed by
/// ordering (INV-4.S04) â€” the last item's key is the largest in the
/// page, and must be >= the previous cursor.
///
/// **Safety (non-regression)**: If the page is non-empty, the returned
/// cursor's `last_key` is `Some(...)`, never `None`.
pub fn extract_checkpoint_cursor(page: &EnumerationPage) -> Option<Cursor> {
    // Connector provided next cursor â†’ use it directly.
    if let Some(ref cursor) = page.next_cursor {
        return Some(cursor.clone());
    }

    // Last page: construct cursor from last item's key.
    if let Some(last_item) = page.items.last() {
        let last_key = last_item.item_key.path.to_vec();
        return Some(Cursor::with_last_key(last_key));
    }

    // Empty page, no cursor â†’ nothing to checkpoint.
    None
}

/// Extract the raw `last_key` bytes from the last item in a page.
///
/// Convenience for callers that need the key bytes directly (e.g.,
/// logging, bounds checking) without constructing a full Cursor.
#[inline]
pub fn last_item_key(page: &EnumerationPage) -> Option<&[u8]> {
    page.items.last().map(|item| item.item_key.path.as_ref())
}

// ---------------------------------------------------------------------------
// Â§3.3 Error Mapping â€” connector errors to coordination actions
// ---------------------------------------------------------------------------

/// The action the runtime should take in response to a connector error.
///
/// This is the result of mapping a connector error (B4 chunk 2) to a
/// coordination action (B2). The mapping is a pure function â€” the
/// runtime may override it based on retry count, circuit breaker
/// state, or operator policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectorAction {
    /// Retry the operation after at least `min_delay_ms`.
    ///
    /// Runtime should apply exponential backoff with jitter on top.
    /// Reference: AWS Architecture Blog, "Exponential Backoff and
    /// Jitter" (2015).
    Retry { min_delay_ms: u32 },

    /// Restart enumeration from `last_key` (discard opaque token).
    ///
    /// Used when pagination token expired but progress is preserved
    /// via the ordered resume key (Spanner query restart pattern).
    RestartFromKey,

    /// Skip the current item and continue with the next.
    ///
    /// Used for item-level read failures (item deleted, permission
    /// denied) where the shard as a whole is fine.
    SkipItem,

    /// Park the shard with the given reason.
    ///
    /// Used when the error is persistent or severe enough that
    /// continued processing is unsafe or wasteful.
    Park { reason: ParkReason },
}

/// Map an `EnumerationError` to a default `ConnectorAction`.
///
/// The runtime MAY override based on: retry count (park after N
/// retries), circuit breaker state (park if open), or operator
/// configuration (custom retry limits per connector).
///
/// Pure function, deterministic.
pub fn map_enumeration_error(err: &EnumerationError) -> ConnectorAction {
    match err {
        EnumerationError::RateLimited { retry_hint, .. } => match retry_hint {
            RetryHint::AfterDelay { delay_ms } => {
                ConnectorAction::Retry { min_delay_ms: *delay_ms }
            }
            RetryHint::Immediately => ConnectorAction::Retry { min_delay_ms: 0 },
            RetryHint::DoNotRetry => ConnectorAction::Park {
                reason: ParkReason::TooManyErrors,
            },
        },

        EnumerationError::AuthFailure { retry_hint, .. } => match retry_hint {
            RetryHint::DoNotRetry => ConnectorAction::Park {
                reason: ParkReason::PermissionDenied,
            },
            RetryHint::AfterDelay { delay_ms } => {
                ConnectorAction::Retry { min_delay_ms: *delay_ms }
            }
            RetryHint::Immediately => ConnectorAction::Retry { min_delay_ms: 0 },
        },

        EnumerationError::SourceError { retry_hint, .. } => match retry_hint {
            RetryHint::DoNotRetry => ConnectorAction::Park {
                reason: ParkReason::Other,
            },
            RetryHint::AfterDelay { delay_ms } => {
                ConnectorAction::Retry { min_delay_ms: *delay_ms }
            }
            RetryHint::Immediately => ConnectorAction::Retry { min_delay_ms: 0 },
        },

        EnumerationError::CursorInvalidated { .. } => ConnectorAction::RestartFromKey,

        EnumerationError::BudgetExhausted { .. } => {
            ConnectorAction::Retry { min_delay_ms: 0 }
        }
    }
}

/// Map a `ReadError` to a default `ConnectorAction`.
///
/// Read errors are item-scoped. Most read failures result in skipping
/// the item rather than parking the shard â€” one deleted file shouldn't
/// stop scanning the entire repository.
///
/// Exception: `AuthFailure { DoNotRetry }` suggests permanently invalid
/// credentials â†’ park the shard.
pub fn map_read_error(err: &ReadError) -> ConnectorAction {
    match err {
        ReadError::ItemNotFound { .. } => ConnectorAction::SkipItem,

        ReadError::PermissionDenied { retry_hint, .. } => match retry_hint {
            RetryHint::DoNotRetry => ConnectorAction::Park {
                reason: ParkReason::PermissionDenied,
            },
            RetryHint::AfterDelay { delay_ms } => {
                ConnectorAction::Retry { min_delay_ms: *delay_ms }
            }
            RetryHint::Immediately => ConnectorAction::Retry { min_delay_ms: 0 },
        },

        ReadError::InvalidRef { .. } => ConnectorAction::SkipItem,

        ReadError::SourceError { retry_hint, .. } => match retry_hint {
            RetryHint::DoNotRetry => ConnectorAction::SkipItem,
            RetryHint::AfterDelay { delay_ms } => {
                ConnectorAction::Retry { min_delay_ms: *delay_ms }
            }
            RetryHint::Immediately => ConnectorAction::Retry { min_delay_ms: 0 },
        },

        ReadError::AuthFailure { retry_hint, .. } => match retry_hint {
            RetryHint::DoNotRetry => ConnectorAction::Park {
                reason: ParkReason::PermissionDenied,
            },
            RetryHint::AfterDelay { delay_ms } => {
                ConnectorAction::Retry { min_delay_ms: *delay_ms }
            }
            RetryHint::Immediately => ConnectorAction::Retry { min_delay_ms: 0 },
        },
    }
}

// ---------------------------------------------------------------------------
// Â§3.4 CircuitState â€” per-connector health tracking
// ---------------------------------------------------------------------------

/// Circuit breaker state for a connector.
///
/// Tracks the health of a connector's external source to prevent the
/// runtime from hammering a failing API. Three states, standard pattern.
///
/// ```text
///   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”    failures >= threshold    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///   â”‚  Closed  â”‚ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â–º  â”‚   Open   â”‚
///   â”‚ (normal) â”‚                             â”‚ (reject) â”‚
///   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                             â””â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜
///        â–²                                        â”‚
///        â”‚  probe succeeds              cooldown  â”‚
///        â”‚                              elapsed   â–¼
///        â”‚                              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///        â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”‚ HalfOpen  â”‚
///                                       â”‚  (probe)  â”‚
///                                       â””â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”˜
///                                  probe      â”‚
///                                  fails      â–¼
///                                       â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///                                       â”‚   Open   â”‚
///                                       â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// ## Invariants
///
/// **Safety (no correctness dependency)**: The circuit breaker is a
/// liveness optimization, NOT a correctness mechanism. A stuck circuit
/// breaker (always closed or always open) affects performance and API
/// health, not scan correctness. Scans delayed by an open circuit are
/// eventually retried when the circuit closes.
///
/// **Liveness (bounded open duration)**: The circuit MUST eventually
/// transition from Open to HalfOpen given time advancement. A
/// permanently open circuit is a liveness violation.
///
/// Reference: Nygard, *Release It!* (2018), Chapter 5;
/// Scanner instructions Â§4.5.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation. Requests pass through. Failures counted.
    Closed {
        /// Consecutive failure count since last success.
        consecutive_failures: u32,
    },

    /// Connector assumed unhealthy. Requests rejected immediately.
    /// Runtime waits for cooldown before probing.
    Open {
        /// Timestamp (ms) when circuit was opened.
        opened_at_ms: u64,
        /// Minimum wait before transitioning to HalfOpen.
        cooldown_ms: u32,
    },

    /// Single probe request allowed. Success â†’ Closed. Failure â†’ Open.
    HalfOpen,
}

impl CircuitState {
    /// Initial state: closed with zero failures.
    #[inline]
    pub fn initial() -> Self {
        Self::Closed { consecutive_failures: 0 }
    }

    /// Returns `true` if the circuit allows requests through.
    #[inline]
    pub fn allows_request(&self) -> bool {
        matches!(self, Self::Closed { .. } | Self::HalfOpen)
    }

    /// Returns `true` if the circuit is open (rejecting requests).
    #[inline]
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    /// Record a successful operation. Resets to Closed.
    pub fn record_success(&mut self) {
        *self = Self::Closed { consecutive_failures: 0 };
    }

    /// Record a failed operation. May trip circuit to Open.
    ///
    /// - **Closed**: increments failure count. If >= threshold â†’ Open.
    /// - **HalfOpen**: probe failed â†’ reopen.
    /// - **Open**: no effect (requests aren't reaching connector).
    pub fn record_failure(&mut self, threshold: u32, now_ms: u64, cooldown_ms: u32) {
        match self {
            Self::Closed { consecutive_failures } => {
                *consecutive_failures += 1;
                if *consecutive_failures >= threshold {
                    *self = Self::Open { opened_at_ms: now_ms, cooldown_ms };
                }
            }
            Self::HalfOpen => {
                *self = Self::Open { opened_at_ms: now_ms, cooldown_ms };
            }
            Self::Open { .. } => {
                // Already open â€” no state change.
            }
        }
    }

    /// Check if Open circuit should transition to HalfOpen.
    ///
    /// Returns `true` and transitions if cooldown elapsed.
    /// Returns `false` (no change) for non-Open states.
    pub fn maybe_half_open(&mut self, now_ms: u64) -> bool {
        if let Self::Open { opened_at_ms, cooldown_ms } = *self {
            if now_ms.saturating_sub(opened_at_ms) >= u64::from(cooldown_ms) {
                *self = Self::HalfOpen;
                return true;
            }
        }
        false
    }
}

/// Configuration for a per-connector circuit breaker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitConfig {
    /// Consecutive failures before the circuit opens.
    pub failure_threshold: u32,
    /// Time (ms) to wait in Open before probing.
    pub cooldown_ms: u32,
}

impl CircuitConfig {
    /// Default: 5 failures, 30-second cooldown.
    ///
    /// Conservative defaults for most API-backed connectors.
    pub fn default_config() -> Self {
        Self { failure_threshold: 5, cooldown_ms: 30_000 }
    }

    /// Aggressive: 3 failures, 60-second cooldown.
    ///
    /// For fragile or rate-limited sources.
    pub fn aggressive() -> Self {
        Self { failure_threshold: 3, cooldown_ms: 60_000 }
    }
}

// ---------------------------------------------------------------------------
// Â§3.5 ConnectorRegistration â€” startup handshake
// ---------------------------------------------------------------------------

/// A connector's registration request to the runtime.
///
/// Bundles `ConnectorInfo` with capability flags. The runtime validates
/// tag uniqueness across all registrations and stores the result.
///
/// ## Lifecycle
///
/// 1. Connector instance is created (connector-specific config).
/// 2. Connector produces `ConnectorRegistration` via `registration()`.
/// 3. Runtime validates: tag unique, at least one capability.
/// 4. Runtime stores registration and routes matching shards to it.
///
/// ## Invariants
///
/// **Safety (tag uniqueness)**: Runtime MUST reject registrations with
/// duplicate tags. Two connectors with the same tag â†’ ItemKey collisions.
///
/// **Safety (capability honesty)**: Connector MUST NOT claim capabilities
/// it doesn't support. Claiming `can_read = true` but always returning
/// `Err` on `open_item` is a liveness violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorRegistration {
    /// Static metadata.
    pub info: ConnectorInfo,

    /// Whether this connector supports enumeration.
    pub can_enumerate: bool,

    /// Whether this connector supports reading.
    pub can_read: bool,

    /// Advisory max concurrent shards. `None` = use runtime defaults.
    pub max_concurrent_shards: Option<u32>,

    /// Recommended default enumeration budget. `None` = use runtime defaults.
    pub recommended_enum_budget: Option<EnumerationBudget>,

    /// Recommended default read budget. `None` = use runtime defaults.
    pub recommended_read_budget: Option<ReadBudget>,
}

impl ConnectorRegistration {
    /// Full-capability registration (enumerate + read).
    pub fn full(info: ConnectorInfo) -> Self {
        Self {
            info,
            can_enumerate: true,
            can_read: true,
            max_concurrent_shards: None,
            recommended_enum_budget: None,
            recommended_read_budget: None,
        }
    }

    /// Enumeration-only registration.
    pub fn enumerate_only(info: ConnectorInfo) -> Self {
        Self {
            info,
            can_enumerate: true,
            can_read: false,
            max_concurrent_shards: None,
            recommended_enum_budget: None,
            recommended_read_budget: None,
        }
    }

    /// Read-only registration.
    pub fn read_only(info: ConnectorInfo) -> Self {
        Self {
            info,
            can_enumerate: false,
            can_read: true,
            max_concurrent_shards: None,
            recommended_enum_budget: None,
            recommended_read_budget: None,
        }
    }

    /// Builder-style: set max concurrent shards.
    pub fn with_max_concurrent_shards(mut self, max: u32) -> Self {
        self.max_concurrent_shards = Some(max);
        self
    }

    /// Builder-style: set recommended enumeration budget.
    pub fn with_enum_budget(mut self, budget: EnumerationBudget) -> Self {
        self.recommended_enum_budget = Some(budget);
        self
    }

    /// Builder-style: set recommended read budget.
    pub fn with_read_budget(mut self, budget: ReadBudget) -> Self {
        self.recommended_read_budget = Some(budget);
        self
    }
}

/// Error when validating a connector registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    /// Another connector already registered with this tag.
    DuplicateTag {
        tag: ConnectorTag,
        existing_name: Box<str>,
        new_name: Box<str>,
    },
    /// Registration claims no capabilities â€” must support at least one.
    NoCapabilities,
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTag { tag, existing_name, new_name } => write!(
                f,
                "duplicate connector tag {:?}: existing={}, new={}",
                tag, existing_name, new_name
            ),
            Self::NoCapabilities => write!(
                f,
                "connector registration has no capabilities \
                 (can_enumerate=false, can_read=false)"
            ),
        }
    }
}

/// Validate a registration against existing registrations.
///
/// Checks: (1) at least one capability, (2) no duplicate tags.
/// Pure function â€” no I/O.
pub fn validate_registration(
    new: &ConnectorRegistration,
    existing: &[ConnectorRegistration],
) -> Result<(), RegistrationError> {
    if !new.can_enumerate && !new.can_read {
        return Err(RegistrationError::NoCapabilities);
    }

    for reg in existing {
        if reg.info.tag == new.info.tag {
            return Err(RegistrationError::DuplicateTag {
                tag: new.info.tag,
                existing_name: reg.info.display_name.clone(),
                new_name: new.info.display_name.clone(),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Â§3.6 ItemOutcome â€” per-item processing result
// ---------------------------------------------------------------------------

/// The outcome of processing a single item after enumeration.
///
/// NOT an error type â€” represents all possible terminal states including
/// success. The runtime aggregates these for shard-level metrics and
/// done-ledger updates (B5).
///
/// ## Design Note
///
/// After enumeration produces `ScanItem` values, the runtime processes
/// each: skip check â†’ read â†’ scan â†’ persist findings. This enum
/// captures the terminal state for progress tracking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemOutcome {
    /// Item scanned successfully. `findings` = count of secrets
    /// detected (may be zero for clean items).
    Scanned { findings: u32 },

    /// Skipped: done-ledger shows already scanned with same strong version.
    SkippedByVersion,

    /// Skipped: content hints indicate binary, scan rules don't cover it.
    SkippedBinary,

    /// Skipped: could not be read (deleted, permission denied, etc.).
    /// Error was non-fatal for the shard.
    SkippedReadError { message: Box<str> },

    /// Content truncated (exceeded read budget). Partial scan performed.
    ScannedTruncated { findings: u32, bytes_read: u64 },
}

impl ItemOutcome {
    /// Number of findings, if scanning occurred.
    pub fn finding_count(&self) -> u32 {
        match self {
            Self::Scanned { findings } | Self::ScannedTruncated { findings, .. } => *findings,
            _ => 0,
        }
    }

    /// Returns `true` if the item was scanned (fully or partially).
    #[inline]
    pub fn was_scanned(&self) -> bool {
        matches!(self, Self::Scanned { .. } | Self::ScannedTruncated { .. })
    }

    /// Returns `true` if the item was skipped for any reason.
    #[inline]
    pub fn was_skipped(&self) -> bool {
        !self.was_scanned()
    }
}

// ============================================================================
// Â§ Invariant Catalog â€” Boundary â‘£ Chunk 3
// ============================================================================
//
// INV-4.S16: validate_page checks ALL of INV-4.S03 (identity), S04
//   (ordering), S05 (budget), S06 (membership), L01 (liveness) in a
//   single pass. No invariant is silently skipped.
//   Verification: test with pages violating each invariant individually
//   and in combination.
//
// INV-4.S17: Cursor extraction monotonicity â€” for a validated page,
//   extract_checkpoint_cursor returns cursor whose last_key >= input
//   cursor's last_key. Guaranteed by ordering invariant (INV-4.S04).
//   Verification: proptest with sorted item sequences.
//
// INV-4.S18: Circuit breaker no-correctness-dependency â€” circuit state
//   is a liveness optimization, never a correctness gate. Stuck circuit
//   (always-closed or always-open) affects performance, not correctness.
//   Verification: code review; simulation with stuck circuit.
//
// INV-4.S19: Error mapping determinism â€” map_enumeration_error and
//   map_read_error are pure functions. Same error â†’ same action.
//   Verification: proptest: call twice with same error, assert same result.
//
// INV-4.S20: Key membership half-open semantics â€” check_key_membership
//   implements [start, end) with empty boundaries meaning unbounded.
//   Same semantics as check_cursor_bounds in B2.
//   Verification: boundary value tests at start, end-1, end.
//
// INV-4.L03: Circuit breaker eventual recovery â€” Open MUST eventually
//   transition to HalfOpen given sufficient time advancement. Permanently
//   open circuit is a liveness violation.
//   Verification: deterministic simulation with time advancement.
//
// Cross-boundary dependencies:
//   - Uses ParkReason from B2 chunk 2 (error mapping target).
//   - Uses Cursor from B2 chunk 1 (extract_checkpoint_cursor output).
//   - Uses ShardSpec from B2 chunk 1 (validate_page, check_key_membership).
//   - Uses ScanItem.check_identity_consistency from B4 chunk 1.
//   - Uses EnumerationPage from B4 chunk 1.
//   - Uses EnumerationError, ReadError, RetryHint from B4 chunk 2.
//   - Feeds ConnectorAction into runtime retry/park decisions (B2).
//   - Feeds ItemOutcome into ShardScanStats (B4 chunk 5) and B5 done-ledger.

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --

    fn test_spec(start: &[u8], end: &[u8]) -> ShardSpec {
        ShardSpec::with_range(start.to_vec(), end.to_vec())
    }

    fn test_budget() -> EnumerationBudget {
        EnumerationBudget::new(100, 30_000, 50)
    }

    fn test_scan_item(path: &[u8]) -> ScanItem {
        let key = ItemKey::new(ConnectorTag::from_ascii(b"test"), path.to_vec());
        let stable_id = key.stable_id();
        ScanItem {
            item_key: key,
            stable_item_id: stable_id,
            item_ref: ItemRef::new(path.to_vec()),
            version: VersionId::strong_from_bytes(b"v1"),
            size_hint: None,
            content_hints: ContentHints::unknown(),
            location: ItemLocation::new("test"),
        }
    }

    // -- check_key_membership --

    #[test]
    fn membership_within_range() {
        assert!(check_key_membership(b"m", &test_spec(b"a", b"z")));
    }

    #[test]
    fn membership_at_start_inclusive() {
        assert!(check_key_membership(b"a", &test_spec(b"a", b"z")));
    }

    #[test]
    fn membership_at_end_exclusive() {
        assert!(!check_key_membership(b"z", &test_spec(b"a", b"z")));
    }

    #[test]
    fn membership_below_range() {
        assert!(!check_key_membership(b"a", &test_spec(b"m", b"z")));
    }

    #[test]
    fn membership_above_range() {
        assert!(!check_key_membership(b"z", &test_spec(b"a", b"m")));
    }

    #[test]
    fn membership_unbounded_start() {
        let spec = ShardSpec::with_range(vec![], b"m".to_vec());
        assert!(check_key_membership(b"a", &spec));
        assert!(!check_key_membership(b"z", &spec));
    }

    #[test]
    fn membership_unbounded_end() {
        let spec = ShardSpec::with_range(b"m".to_vec(), vec![]);
        assert!(!check_key_membership(b"a", &spec));
        assert!(check_key_membership(b"z", &spec));
    }

    #[test]
    fn membership_fully_unbounded() {
        assert!(check_key_membership(b"anything", &ShardSpec::unbounded()));
    }

    // -- validate_page --

    #[test]
    fn validate_empty_page_valid() {
        let page = EnumerationPage {
            items: vec![],
            next_cursor: None,
            api_calls_used: 0,
        };
        assert!(validate_page(&page, &test_spec(b"a", b"z"), &test_budget()).is_valid());
    }

    #[test]
    fn validate_liveness_violation() {
        let page = EnumerationPage {
            items: vec![],
            next_cursor: Some(Cursor::initial()),
            api_calls_used: 0,
        };
        let result = validate_page(&page, &test_spec(b"a", b"z"), &test_budget());
        assert!(!result.is_valid());
        assert!(result.liveness_violation);
    }

    #[test]
    fn validate_budget_exceeded() {
        let budget = EnumerationBudget::new(2, 30_000, 50);
        let page = EnumerationPage {
            items: vec![test_scan_item(b"a"), test_scan_item(b"b"), test_scan_item(b"c")],
            next_cursor: None,
            api_calls_used: 1,
        };
        let result = validate_page(&page, &test_spec(b"a", b"z"), &budget);
        assert!(result.budget_exceeded);
    }

    // -- error mapping --

    #[test]
    fn map_rate_limit_retry() {
        let err = EnumerationError::RateLimited {
            retry_hint: RetryHint::AfterDelay { delay_ms: 5000 },
            message: "429".into(),
        };
        assert_eq!(
            map_enumeration_error(&err),
            ConnectorAction::Retry { min_delay_ms: 5000 },
        );
    }

    #[test]
    fn map_cursor_invalidated_restarts() {
        let err = EnumerationError::CursorInvalidated {
            last_valid_key: Some(b"key".to_vec().into_boxed_slice()),
            message: "expired".into(),
        };
        assert_eq!(map_enumeration_error(&err), ConnectorAction::RestartFromKey);
    }

    #[test]
    fn map_auth_permanent_parks() {
        let err = EnumerationError::AuthFailure {
            retry_hint: RetryHint::DoNotRetry,
            message: "revoked".into(),
        };
        assert_eq!(
            map_enumeration_error(&err),
            ConnectorAction::Park { reason: ParkReason::PermissionDenied },
        );
    }

    #[test]
    fn map_read_not_found_skips() {
        let err = ReadError::ItemNotFound { message: "404".into() };
        assert_eq!(map_read_error(&err), ConnectorAction::SkipItem);
    }

    #[test]
    fn map_read_invalid_ref_skips() {
        let err = ReadError::InvalidRef { message: "expired URL".into() };
        assert_eq!(map_read_error(&err), ConnectorAction::SkipItem);
    }

    // -- CircuitState --

    #[test]
    fn circuit_initial_closed() {
        let c = CircuitState::initial();
        assert!(c.allows_request());
        assert!(!c.is_open());
    }

    #[test]
    fn circuit_opens_after_threshold() {
        let mut c = CircuitState::initial();
        for _ in 0..4 {
            c.record_failure(5, 1000, 30_000);
            assert!(c.allows_request());
        }
        c.record_failure(5, 1000, 30_000); // 5th failure
        assert!(c.is_open());
        assert!(!c.allows_request());
    }

    #[test]
    fn circuit_half_open_after_cooldown() {
        let mut c = CircuitState::Open { opened_at_ms: 1000, cooldown_ms: 5000 };
        assert!(!c.maybe_half_open(3000)); // too early
        assert!(c.maybe_half_open(6000)); // cooldown elapsed
        assert_eq!(c, CircuitState::HalfOpen);
    }

    #[test]
    fn circuit_half_open_success_closes() {
        let mut c = CircuitState::HalfOpen;
        c.record_success();
        assert_eq!(c, CircuitState::Closed { consecutive_failures: 0 });
    }

    #[test]
    fn circuit_half_open_failure_reopens() {
        let mut c = CircuitState::HalfOpen;
        c.record_failure(5, 2000, 30_000);
        assert!(c.is_open());
    }

    #[test]
    fn circuit_success_resets_failures() {
        let mut c = CircuitState::Closed { consecutive_failures: 4 };
        c.record_success();
        assert_eq!(c, CircuitState::Closed { consecutive_failures: 0 });
    }

    // -- ConnectorRegistration --

    #[test]
    fn registration_full_both_capabilities() {
        let info = ConnectorInfo::new(ConnectorTag::from_ascii(b"test"), "Test", "1.0");
        let reg = ConnectorRegistration::full(info);
        assert!(reg.can_enumerate && reg.can_read);
    }

    #[test]
    fn validate_registration_rejects_duplicate() {
        let info1 = ConnectorInfo::new(ConnectorTag::from_ascii(b"gh"), "GH v1", "1.0");
        let info2 = ConnectorInfo::new(ConnectorTag::from_ascii(b"gh"), "GH v2", "2.0");
        let existing = vec![ConnectorRegistration::full(info1)];
        assert!(matches!(
            validate_registration(&ConnectorRegistration::full(info2), &existing),
            Err(RegistrationError::DuplicateTag { .. }),
        ));
    }

    #[test]
    fn validate_registration_accepts_unique() {
        let info1 = ConnectorInfo::new(ConnectorTag::from_ascii(b"gh"), "GitHub", "1.0");
        let info2 = ConnectorInfo::new(ConnectorTag::from_ascii(b"gl"), "GitLab", "1.0");
        let existing = vec![ConnectorRegistration::full(info1)];
        assert!(validate_registration(&ConnectorRegistration::full(info2), &existing).is_ok());
    }

    #[test]
    fn validate_registration_rejects_no_capabilities() {
        let info = ConnectorInfo::new(ConnectorTag::from_ascii(b"no"), "No-Op", "0.0");
        let reg = ConnectorRegistration {
            info,
            can_enumerate: false,
            can_read: false,
            max_concurrent_shards: None,
            recommended_enum_budget: None,
            recommended_read_budget: None,
        };
        assert!(matches!(
            validate_registration(&reg, &[]),
            Err(RegistrationError::NoCapabilities),
        ));
    }

    // -- ItemOutcome --

    #[test]
    fn outcome_scanned_counts() {
        let o = ItemOutcome::Scanned { findings: 3 };
        assert_eq!(o.finding_count(), 3);
        assert!(o.was_scanned());
    }

    #[test]
    fn outcome_skipped_zero() {
        assert_eq!(ItemOutcome::SkippedByVersion.finding_count(), 0);
        assert!(ItemOutcome::SkippedByVersion.was_skipped());
    }

    #[test]
    fn outcome_truncated() {
        let o = ItemOutcome::ScannedTruncated { findings: 1, bytes_read: 1024 };
        assert_eq!(o.finding_count(), 1);
        assert!(o.was_scanned());
    }

    // -- PageValidation Display --

    #[test]
    fn page_validation_valid_display() {
        assert_eq!(format!("{}", PageValidation::default()), "page valid");
    }

    #[test]
    fn page_validation_invalid_display() {
        let v = PageValidation {
            identity_mismatches: vec![2],
            liveness_violation: true,
            ..Default::default()
        };
        let s = format!("{}", v);
        assert!(s.contains("FAILED") && s.contains("identity_mismatches"));
    }

    // -- Property test stubs --

    // TODO: proptest for validate_page: sorted, in-range, identity-consistent
    //   items always produce is_valid() == true.
    //
    // TODO: proptest for check_key_membership agreement with B2
    //   check_cursor_bounds.
    //
    // TODO: proptest for circuit breaker liveness: âˆ€ failure sequences,
    //   âˆƒ time t: circuit.maybe_half_open(t) == true.
    //
    // TODO: proptest for error mapping determinism: call twice, same result.
}
