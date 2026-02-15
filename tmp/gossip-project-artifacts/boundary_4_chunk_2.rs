//! Boundary â‘£ â€” Connector Contract: Chunk 2 (DRAFT)
//!
//! Enumeration and Reading traits: the contract that all connector
//! implementations (GitHub, S3, GitLab, Confluence, local filesystem,
//! deterministic test stub) must implement.
//!
//! This file is additive to Boundaries â‘ â€“â‘¢ (all chunks) and Boundary â‘£
//! chunk 1 (value types).
//!
//! ## Problem Statement
//!
//! The runtime needs two operations from each connector:
//!
//! 1. **Enumerate**: Given a shard spec and cursor, produce the next page
//!    of scan items within the shard's key range. This is the "discovery"
//!    phase â€” finding what needs scanning.
//!
//! 2. **Read**: Given an `ItemRef` from enumeration, open and return a
//!    byte stream of the item's content. This is the "retrieval" phase â€”
//!    fetching content for the scanner engine.
//!
//! These are deliberately separate traits because:
//! - Some deployments may enumerate from one source and read from another
//!   (e.g., enumerate from an API, read from a cache).
//! - Testing benefits from independent stubs (mock enumeration without
//!   needing real content).
//! - Different scaling characteristics: enumeration is metadata-bound,
//!   reading is bandwidth-bound.
//!
//! ## Design Decisions (locked)
//!
//! D4.10: Enumeration and reading are separate traits, NOT a single
//!        "Connector" super-trait.
//!
//!        **Why**: Separation of concerns. The runtime orchestrates
//!        enumeration (driven by the coordinator's shard loop) and
//!        reading (driven by the scanner pipeline) independently.
//!        A connector that can enumerate but temporarily can't read
//!        (e.g., credential rotation window) should be expressible.
//!
//!        This follows the Interface Segregation Principle (ISP) and
//!        matches the pattern in FoundationDB's layered architecture
//!        where each layer has a narrow interface.
//!
//!        Reference: FoundationDB Record Layer (Chrysafis et al., 2019)
//!        â€” narrow per-layer contracts enable independent evolution.
//!
//! D4.11: Both traits are synchronous (blocking I/O), matching B2's
//!        coordination trait (D2.13).
//!
//!        **Why**: The contract defines semantics, not execution model.
//!        The runtime wraps connector calls in its scheduling model
//!        (e.g., blocking threads, spawn_blocking, or deterministic
//!        simulation). This keeps the contract testable without an
//!        async runtime.
//!
//!        In practice, connectors perform blocking network I/O. The
//!        runtime's thread pool provides concurrency at the shard level;
//!        within a shard, enumeration pages are processed sequentially,
//!        which is the natural model for cursor-based pagination.
//!
//!        Reference: FoundationDB simulation â€” synchronous semantics
//!        with simulated scheduling (Zhou et al., SIGMOD 2021).
//!
//! D4.12: `enumerate_page` takes `&self`, NOT `&mut self`.
//!
//!        **Why**: Enumeration is logically read-only from the
//!        connector's perspective â€” it's querying the source system.
//!        Interior mutability (e.g., connection pool, rate-limiter
//!        state) is the connector's concern, hidden behind `&self`.
//!
//!        This matches cursor-based pagination: all progress state is
//!        in the cursor argument, not in the connector itself. The
//!        connector is stateless w.r.t. enumeration progress.
//!
//!        If a connector needs mutable state for enumeration (unlikely),
//!        it can use internal `Mutex` or `RefCell`. The contract does
//!        not prohibit this â€” it merely expresses that enumeration
//!        is re-entrant for different shards.
//!
//! D4.13: `open_item` returns a `Box<dyn Read>`, NOT raw bytes.
//!
//!        **Why**: Items can be arbitrarily large (multi-GiB files).
//!        Returning `Vec<u8>` forces the entire content into memory.
//!        A `Read` trait object lets the scanner stream content through
//!        its chunking/scanning pipeline without materializing it all.
//!
//!        `Box<dyn Read>` is the simplest streaming abstraction in
//!        synchronous Rust. It works with the blocking I/O model
//!        (D4.11) and composes naturally with `BufReader`,
//!        `io::copy`, and the scanner's chunk boundary handling (Â§5.1).
//!
//!        The `ReadBudget.max_bytes` limit is enforced by the caller
//!        wrapping the reader in a `Take` adapter, NOT by the connector
//!        itself. This keeps the connector simple and the budget
//!        enforcement uniform.
//!
//!        Reference: Dean & Ghemawat, "MapReduce" (OSDI 2004) â€”
//!        input splits produce record readers, not materialized arrays.
//!
//! D4.14: Error types follow B2's operation-specific pattern (D2.16).
//!
//!        **Why**: Connector errors have different failure modes than
//!        coordination errors. Enumeration can fail due to rate
//!        limiting, authentication, or source unavailability. Reading
//!        can fail due to item deletion, corruption, or timeout.
//!        Operation-specific error types let callers pattern-match on
//!        relevant variants without casting.
//!
//! D4.15: Errors carry `RetryHint` to guide the runtime's retry strategy.
//!
//!        **Why**: The runtime (not the connector) owns the retry loop.
//!        But the connector has the best information about whether a
//!        failure is transient (rate limit â†’ retry after N seconds) or
//!        permanent (item deleted â†’ park or skip).
//!
//!        `RetryHint` conveys this without giving the connector control
//!        over retry policy. The runtime is free to ignore the hint or
//!        apply its own backoff strategy on top.
//!
//!        Reference: Nygard, *Release It!* (2018) â€” circuit breaker
//!        pattern, where the wrapped component signals recoverability.
//!        AWS SDKs return `retryable` flags on errors.
//!
//! D4.16: `ConnectorInfo` provides static metadata about the connector
//!        for observability and registration, NOT for runtime behavior.
//!
//!        **Why**: The runtime needs the connector's `ConnectorTag` to
//!        validate `ItemKey` consistency, and its version string for
//!        metrics/logging. This is fetched once at startup, not per-call.

// Assumes all types from prior boundaries and B4 chunk 1 are in scope:
// use crate::{
//     ConnectorTag, ItemKey, StableItemId, ObjectVersionId,
//     ShardSpec, Cursor,
//     VersionId, ItemRef, ContentHints, ItemLocation,
//     ScanItem, EnumerationPage, EnumerationBudget, ReadBudget,
// };

use core::fmt;
use std::io::Read;

// ============================================================================
// Â§ Chunk 2: Connector Traits & Error Types
// ============================================================================

// ---------------------------------------------------------------------------
// Â§2.1 RetryHint â€” connector advice on error recoverability
// ---------------------------------------------------------------------------

/// Connector's advice to the runtime on whether/how to retry.
///
/// The runtime owns the retry loop and backoff strategy. `RetryHint`
/// is advisory â€” the runtime MAY ignore it. But connectors have domain
/// knowledge about failure modes that the runtime lacks:
///
/// - A 429 from GitHub means "wait N seconds" â†’ `AfterDelay`
/// - A 404 for a file means "it was deleted" â†’ `DoNotRetry`
/// - A network timeout is ambiguous â†’ `Immediately`
///
/// ## Invariants
///
/// **Safety (advisory only)**: The runtime MUST NOT rely on RetryHint
/// for correctness. A connector that always returns `Immediately` is
/// valid (just suboptimal). A connector that returns `DoNotRetry` for
/// a transient error may cause unnecessary parks.
///
/// **Liveness (bounded retries)**: The runtime MUST impose a maximum
/// retry count regardless of RetryHint. Infinite retry loops on
/// `Immediately` hints must be impossible.
///
/// Reference: AWS SDK retry behavior (exponential backoff with jitter,
/// respecting Retry-After headers); Nygard, *Release It!* (2018),
/// Chapter 5 â€” stability patterns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetryHint {
    /// The error is transient. Retry immediately (subject to the
    /// runtime's backoff policy).
    ///
    /// Use for: network timeouts, transient server errors (500, 502, 503).
    Immediately,

    /// The error is transient but the source has signaled a wait.
    /// `delay_ms` is the minimum milliseconds to wait before retry.
    ///
    /// Use for: rate limit responses (429), server-requested backoff.
    ///
    /// The runtime SHOULD wait at least `delay_ms` but MAY add jitter.
    AfterDelay { delay_ms: u32 },

    /// The error is permanent for this item/page. Do not retry.
    ///
    /// Use for: item deleted (404), permission denied (403),
    /// invalid item ref (corrupt data).
    ///
    /// The runtime should skip the item or park the shard.
    DoNotRetry,
}

impl RetryHint {
    /// Returns `true` if this hint suggests retrying.
    #[inline]
    pub fn should_retry(&self) -> bool {
        !matches!(self, Self::DoNotRetry)
    }
}

// ---------------------------------------------------------------------------
// Â§2.2 EnumerationError â€” failures during enumerate_page
// ---------------------------------------------------------------------------

/// Error from an `enumerate_page` call.
///
/// Enumeration errors fall into three categories:
///
/// 1. **Transient source errors**: rate limits, timeouts, server errors.
///    These are retryable and the runtime should back off and retry.
///
/// 2. **Authentication/authorization failures**: expired credentials,
///    revoked access. The runtime should attempt credential refresh
///    and retry, or park the shard.
///
/// 3. **Cursor invalidation**: the source's pagination state has become
///    invalid (e.g., a repository was force-pushed between pages, or
///    the API's continuation token expired). The runtime must decide
///    whether to restart enumeration from `cursor.last_key` (discarding
///    the opaque token) or park the shard.
///
/// ## Design Note: Why no "ShardNotFound" or lease errors?
///
/// Enumeration is a connector operation, not a coordination operation.
/// The connector doesn't know about shards or leases â€” it receives a
/// `ShardSpec` and `Cursor` as opaque parameters. Shard-level errors
/// (wrong tenant, expired lease) are caught by the coordination layer
/// BEFORE calling the connector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnumerationError {
    /// The source API returned a rate-limit error.
    ///
    /// `retry_hint` typically contains `AfterDelay` with the server's
    /// requested wait time.
    RateLimited {
        retry_hint: RetryHint,
        message: Box<str>,
    },

    /// Authentication or authorization failure.
    ///
    /// The connector's credentials are invalid, expired, or revoked.
    /// The runtime should attempt credential refresh before retrying.
    AuthFailure {
        retry_hint: RetryHint,
        message: Box<str>,
    },

    /// The source API returned an error that doesn't fit other categories.
    ///
    /// Includes transient server errors (5xx), network timeouts, and
    /// unexpected response formats.
    SourceError {
        retry_hint: RetryHint,
        message: Box<str>,
    },

    /// The opaque cursor token is no longer valid.
    ///
    /// The source's pagination state has been invalidated. This can
    /// happen when:
    /// - The API's continuation token expired (time-limited tokens)
    /// - The underlying data changed (force push, deletion)
    /// - The source was restarted and lost pagination state
    ///
    /// When this occurs, the runtime has two recovery options:
    /// 1. Restart enumeration from `cursor.last_key` (discard the
    ///    opaque token, re-enumerate from the last committed key).
    ///    This works because `last_key` is our stable progress
    ///    marker â€” the opaque token is just an optimization.
    /// 2. Park the shard if re-enumeration is too expensive.
    ///
    /// Reference: Spanner query restart (Bacon et al., 2017) â€” the
    /// ordered resume key (`last_key`) is the fallback when the
    /// opaque restart token fails. This is exactly D2.1.
    CursorInvalidated {
        /// The last_key that was valid. The runtime can construct a
        /// new cursor with this key and no token to restart.
        last_valid_key: Option<Box<[u8]>>,
        message: Box<str>,
    },

    /// The budget was exhausted before enumeration could produce any
    /// results. This is NOT a failure â€” it's a signal that the budget
    /// was too small for even one page of results.
    ///
    /// The runtime should retry with a larger budget, particularly
    /// `max_api_calls` if the source requires multiple API calls per
    /// item. `retry_hint` is always `Immediately`.
    BudgetExhausted {
        /// Which budget field was exhausted first.
        exhausted_field: BudgetField,
    },
}

/// Which budget field was exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetField {
    Items,
    WallTime,
    ApiCalls,
}

impl EnumerationError {
    /// Returns the retry hint for this error, if applicable.
    pub fn retry_hint(&self) -> RetryHint {
        match self {
            Self::RateLimited { retry_hint, .. } => retry_hint.clone(),
            Self::AuthFailure { retry_hint, .. } => retry_hint.clone(),
            Self::SourceError { retry_hint, .. } => retry_hint.clone(),
            Self::CursorInvalidated { .. } => RetryHint::Immediately,
            Self::BudgetExhausted { .. } => RetryHint::Immediately,
        }
    }

    /// Returns `true` if this error suggests cursor restart rather
    /// than simple retry.
    #[inline]
    pub fn needs_cursor_restart(&self) -> bool {
        matches!(self, Self::CursorInvalidated { .. })
    }
}

impl fmt::Display for EnumerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RateLimited { message, .. } => write!(f, "rate limited: {message}"),
            Self::AuthFailure { message, .. } => write!(f, "auth failure: {message}"),
            Self::SourceError { message, .. } => write!(f, "source error: {message}"),
            Self::CursorInvalidated { message, .. } => {
                write!(f, "cursor invalidated: {message}")
            }
            Self::BudgetExhausted { exhausted_field } => {
                write!(f, "budget exhausted: {exhausted_field:?}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Â§2.3 ReadError â€” failures during open_item
// ---------------------------------------------------------------------------

/// Error from an `open_item` call.
///
/// Read errors represent failures to retrieve an item's content AFTER
/// it was successfully enumerated. The item existed at enumeration
/// time but may have become unavailable by read time.
///
/// ## Error Categories
///
/// 1. **Item unavailable**: deleted, moved, or permission revoked
///    between enumeration and read. Permanent for this scan cycle.
///
/// 2. **Transient source errors**: server errors, network issues.
///    Retryable.
///
/// 3. **Ref invalidation**: the ItemRef is malformed or expired,
///    requiring re-enumeration to obtain a fresh reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The item no longer exists at the source.
    ///
    /// This is permanent for this scan cycle. The runtime should
    /// skip this item (it may reappear in a future scan if
    /// recreated).
    ItemNotFound {
        message: Box<str>,
    },

    /// The item exists but the connector lacks permission to read it.
    ///
    /// This may be transient (credential rotation) or permanent
    /// (access revoked). The `retry_hint` distinguishes.
    PermissionDenied {
        retry_hint: RetryHint,
        message: Box<str>,
    },

    /// The `ItemRef` is malformed or expired.
    ///
    /// This can happen if:
    /// - The `ItemRef` contained a pre-signed URL that expired
    /// - The connector's internal format changed between versions
    /// - Data corruption
    ///
    /// Typically permanent. The runtime should re-enumerate the item
    /// to get a fresh `ItemRef`.
    InvalidRef {
        message: Box<str>,
    },

    /// A transient error occurred while reading.
    ///
    /// Network timeouts, server errors, etc. Retryable.
    SourceError {
        retry_hint: RetryHint,
        message: Box<str>,
    },

    /// Authentication or authorization failure.
    AuthFailure {
        retry_hint: RetryHint,
        message: Box<str>,
    },
}

impl ReadError {
    /// Returns the retry hint for this error.
    pub fn retry_hint(&self) -> RetryHint {
        match self {
            Self::ItemNotFound { .. } => RetryHint::DoNotRetry,
            Self::PermissionDenied { retry_hint, .. } => retry_hint.clone(),
            Self::InvalidRef { .. } => RetryHint::DoNotRetry,
            Self::SourceError { retry_hint, .. } => retry_hint.clone(),
            Self::AuthFailure { retry_hint, .. } => retry_hint.clone(),
        }
    }

    /// Returns `true` if this error means the item should be
    /// re-enumerated (fresh `ItemRef`) rather than retried with
    /// the same `ItemRef`.
    #[inline]
    pub fn needs_re_enumeration(&self) -> bool {
        matches!(self, Self::InvalidRef { .. })
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ItemNotFound { message } => write!(f, "item not found: {message}"),
            Self::PermissionDenied { message, .. } => {
                write!(f, "permission denied: {message}")
            }
            Self::InvalidRef { message } => write!(f, "invalid item ref: {message}"),
            Self::SourceError { message, .. } => write!(f, "source error: {message}"),
            Self::AuthFailure { message, .. } => write!(f, "auth failure: {message}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Â§2.4 ReadResult â€” successful open_item outcome
// ---------------------------------------------------------------------------

/// Successful result of an `open_item` call.
///
/// Contains the content reader and metadata about the retrieved content.
/// The `actual_version` field allows the runtime to detect version
/// changes between enumeration and read time.
///
/// ## Version Consistency Check
///
/// If `actual_version != enumerated_version`, the item was modified
/// between enumeration and read. The runtime must decide:
/// - Use the content anyway (acceptable for secret scanning â€” we
///   scan what we got, and the next enumeration will pick up the
///   new version).
/// - Discard and re-enumerate (if strict version consistency is
///   required for dedup).
///
/// In practice, using the content is almost always correct for
/// secret scanning â€” we're looking for secrets, not maintaining
/// transactional consistency on file versions.
///
/// ## Invariants
///
/// **Safety (budget enforcement)**: The runtime MUST wrap `reader`
/// in a `Take` adapter using `ReadBudget.max_bytes` to enforce the
/// byte limit. The connector is NOT responsible for budget enforcement
/// on the read path.
///
/// **Liveness (reader validity)**: The `reader` MUST be readable
/// until dropped. The connector MUST NOT close underlying connections
/// or revoke credentials while a `ReadResult` is live.
pub struct ReadResult {
    /// Byte stream of the item's content.
    ///
    /// The runtime wraps this in `BufReader` and `Take` for buffered,
    /// budget-limited reading.
    pub reader: Box<dyn Read>,

    /// The version of the content actually retrieved.
    ///
    /// This MAY differ from the `VersionId` reported at enumeration
    /// time if the item was modified between enumeration and read.
    /// `None` if the connector cannot determine the read-time version
    /// (some sources don't return version metadata on read).
    pub actual_version: Option<VersionId>,

    /// Actual content size in bytes, if known at open time.
    ///
    /// Some sources provide Content-Length or equivalent before the
    /// read starts. `None` if the size is unknown until the read
    /// completes (e.g., chunked transfer encoding).
    pub actual_size: Option<u64>,
}

impl fmt::Debug for ReadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadResult")
            .field("actual_version", &self.actual_version)
            .field("actual_size", &self.actual_size)
            .field("reader", &"<dyn Read>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Â§2.5 ConnectorInfo â€” static connector metadata
// ---------------------------------------------------------------------------

/// Static metadata about a connector implementation.
///
/// Fetched once at startup for registration and observability.
/// Does NOT change during the connector's lifetime.
///
/// ## Invariants
///
/// **Safety (tag stability)**: `tag` MUST be the same value the
/// connector uses in all `ItemKey` constructions. If a connector
/// reports `tag = "github"` here but constructs `ItemKey`s with
/// `tag = "gh"`, identity consistency is broken.
///
/// **Safety (tag uniqueness)**: No two active connectors in the
/// same deployment may share a `ConnectorTag`. The runtime asserts
/// this at registration time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorInfo {
    /// The connector's stable tag, used in all `ItemKey` constructions.
    pub tag: ConnectorTag,

    /// Human-readable name for dashboards and logs.
    /// E.g., `"GitHub App Connector"`, `"S3 Bucket Scanner"`.
    pub display_name: Box<str>,

    /// Version string for the connector implementation.
    /// E.g., `"1.2.3"`, `"0.1.0-alpha"`.
    ///
    /// Used for metrics labels and debugging, not for compatibility
    /// checks. The contract version is implicit in the trait itself.
    pub version: Box<str>,
}

impl ConnectorInfo {
    pub fn new(tag: ConnectorTag, display_name: &str, version: &str) -> Self {
        Self {
            tag,
            display_name: display_name.into(),
            version: version.into(),
        }
    }
}

impl fmt::Display for ConnectorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{} ({:?})", self.display_name, self.version, self.tag)
    }
}

// ---------------------------------------------------------------------------
// Â§2.6 EnumerationConnector trait
// ---------------------------------------------------------------------------

/// The enumeration contract for connectors.
///
/// A connector implements this trait to produce `ScanItem` pages from
/// a source system. The runtime calls `enumerate_page` in a loop,
/// advancing the cursor on each call, until the shard is exhausted
/// (last page) or the shard's lease expires.
///
/// ## Call Sequence
///
/// ```text
///   let info = connector.info();
///   assert!(info.tag == expected_tag);  // registration check
///
///   // Shard loop (driven by coordinator)
///   let mut cursor = restored_cursor;   // from coordinator
///   loop {
///       let budget = compute_budget(lease_remaining, pipeline_pressure);
///       match connector.enumerate_page(&spec, &cursor, &budget) {
///           Ok(page) => {
///               page.assert_ordering();                    // INV-4.4
///               page.assert_all_identity_consistent();     // INV-4.3
///               assert!(page.items.len() <= budget.max_items as usize); // INV-4.5
///
///               process_items(&page.items);
///               coordinator.checkpoint(new_cursor, op_id)?;
///
///               match page.next_cursor {
///                   Some(next) => cursor = next,
///                   None => { coordinator.complete(...)?; break; }
///               }
///           }
///           Err(EnumerationError::CursorInvalidated { last_valid_key, .. }) => {
///               // Restart from last_key, discard opaque token (D2.1)
///               cursor = Cursor::from_key_only(last_valid_key);
///           }
///           Err(e) if e.retry_hint().should_retry() => {
///               apply_backoff(e.retry_hint());
///               continue;
///           }
///           Err(e) => {
///               coordinator.park_shard(ParkReason::EnumerationFailed, ...)?;
///               break;
///           }
///       }
///   }
/// ```
///
/// ## Invariants (must hold across ALL implementations)
///
/// **Safety (membership)**: All items in the returned page have
/// `item_key.path` within `[spec.key_range_start, spec.key_range_end)`.
///
/// **Safety (ordering)**: Items within a page are in non-decreasing
/// `item_key` order.
///
/// **Safety (identity consistency)**: For every item,
/// `stable_item_id == item_key.stable_id()`.
///
/// **Safety (budget compliance)**: `page.items.len() <= budget.max_items`.
///
/// **Safety (cursor advancement)**: The `next_cursor.last_key` (if
/// present) is >= the last item's key and >= `cursor.last_key`
/// (monotonicity).
///
/// **Liveness (progress)**: Under a non-zero budget, the call either:
/// - Returns at least one item, OR
/// - Returns `next_cursor == None` (exhausted), OR
/// - Returns an error.
///
/// Zero items + `Some(cursor)` + `Ok` = liveness violation.
///
/// ## Verification Strategy
///
/// - Deterministic test connector with canned data for unit tests.
/// - Property-based testing: random ShardSpec ranges, verify all
///   items fall within range and are ordered.
/// - Integration tests per real connector with live source.
/// - Deterministic simulation: inject rate limits, token expirations,
///   crashes mid-page.
pub trait EnumerationConnector {
    /// Return static metadata about this connector.
    ///
    /// Called once at registration. The runtime asserts tag uniqueness
    /// and records the info for metrics/logging.
    fn info(&self) -> ConnectorInfo;

    /// Enumerate the next page of scan items within the shard's key range.
    ///
    /// ## Parameters
    ///
    /// - `spec`: The shard's key range and connector-opaque metadata.
    ///   The connector uses `spec.key_range_start` and
    ///   `spec.key_range_end` to bound its query, and
    ///   `spec.connector_meta` for source-specific context (e.g.,
    ///   repository coordinates, bucket name).
    ///
    /// - `cursor`: The current progress state. On the first call for a
    ///   shard, this is `Cursor::initial()` (no last_key, no token).
    ///   On subsequent calls, this is the `next_cursor` from the
    ///   previous page.
    ///
    /// - `budget`: Resource limits for this call. The connector MUST
    ///   return before exceeding any limit.
    ///
    /// ## Returns
    ///
    /// `Ok(EnumerationPage)` with the items and next cursor, or
    /// `Err(EnumerationError)` with a retry hint.
    fn enumerate_page(
        &self,
        spec: &ShardSpec,
        cursor: &Cursor,
        budget: &EnumerationBudget,
    ) -> Result<EnumerationPage, EnumerationError>;
}

// ---------------------------------------------------------------------------
// Â§2.7 ReadConnector trait
// ---------------------------------------------------------------------------

/// The reading contract for connectors.
///
/// A connector implements this trait to retrieve item content by
/// `ItemRef`. The runtime calls `open_item` after enumeration, for
/// items that pass the done-ledger skip check (i.e., items that need
/// scanning).
///
/// ## Usage
///
/// ```text
///   match reader_connector.open_item(&item_ref, &budget) {
///       Ok(result) => {
///           let limited = result.reader.take(budget.max_bytes);
///           let mut buf_reader = BufReader::new(limited);
///           scanner.scan(&mut buf_reader, &scan_context)?;
///       }
///       Err(ReadError::ItemNotFound { .. }) => {
///           // Item deleted between enum and read. Skip, log warning.
///       }
///       Err(ReadError::InvalidRef { .. }) => {
///           // Need fresh ItemRef. Re-enumerate this item.
///       }
///       Err(e) if e.retry_hint().should_retry() => {
///           apply_backoff(e.retry_hint());
///           // Retry open_item with same ItemRef
///       }
///       Err(e) => {
///           // Permanent failure. Park or skip.
///       }
///   }
/// ```
///
/// ## Invariants (must hold across ALL implementations)
///
/// **Safety (ref opacity)**: The connector MUST accept any `ItemRef`
/// it previously produced. An `ItemRef` from connector A passed to
/// connector B is undefined behavior (the runtime must prevent this).
///
/// **Safety (reader validity)**: The returned reader MUST remain
/// valid (readable, not closed) until it is dropped. The connector
/// MUST NOT close underlying resources while a `ReadResult` is live.
///
/// **Liveness (progress)**: Reads from the returned reader MUST make
/// progress (return data or EOF) within a bounded time. The runtime
/// enforces this externally via timeouts, but the connector should
/// not block indefinitely on a single read.
///
/// ## Verification Strategy
///
/// - Deterministic test connector returning canned byte streams.
/// - Property-based testing: content round-trip (enumerate â†’ read â†’
///   verify bytes match expected content).
/// - Integration tests: read real items from live sources.
/// - Fault injection: simulate partial reads, connection resets,
///   stale ItemRefs.
pub trait ReadConnector {
    /// Return static metadata about this connector.
    ///
    /// Must return the SAME `ConnectorInfo` as the corresponding
    /// `EnumerationConnector`. In deployments where enumeration and
    /// reading are the same connector instance, this is trivially
    /// satisfied.
    fn info(&self) -> ConnectorInfo;

    /// Open an item for reading.
    ///
    /// ## Parameters
    ///
    /// - `item_ref`: Opaque reference produced by enumeration.
    ///   Contains whatever the connector needs to locate and
    ///   authenticate access to the item.
    ///
    /// - `budget`: Resource limits for the read. The runtime enforces
    ///   `max_bytes` via `Take`, but the connector should respect
    ///   `max_wall_time_ms` as guidance for connection timeouts.
    ///
    /// ## Returns
    ///
    /// `Ok(ReadResult)` with a byte stream and optional metadata, or
    /// `Err(ReadError)` with a retry hint.
    fn open_item(
        &self,
        item_ref: &ItemRef,
        budget: &ReadBudget,
    ) -> Result<ReadResult, ReadError>;
}

// ---------------------------------------------------------------------------
// Â§2.8 Connector â€” convenience trait combining both
// ---------------------------------------------------------------------------

/// A connector that supports both enumeration and reading.
///
/// Most connector implementations provide both capabilities. This
/// trait is a convenience for the common case â€” the runtime can
/// accept either separate `EnumerationConnector` + `ReadConnector`
/// implementations or a single `Connector`.
///
/// ## Note
///
/// This trait has a blanket implementation for any type that
/// implements both `EnumerationConnector` and `ReadConnector`.
/// Connectors should implement the two sub-traits, not this one.
pub trait Connector: EnumerationConnector + ReadConnector {}

// Blanket impl: any type implementing both sub-traits is a Connector.
impl<T: EnumerationConnector + ReadConnector> Connector for T {}

// ============================================================================
// Â§ Invariant Catalog â€” Boundary â‘£ Chunk 2
// ============================================================================
//
// INV-4.10 (Safety, trait separation correctness):
//   The runtime MUST NOT pass an `ItemRef` from connector A to
//   connector B's `open_item`. `ItemRef` is scoped to the connector
//   instance that produced it.
//   Violation: undefined behavior (likely read failure or wrong content).
//   Verification: runtime type-level or tag-based enforcement.
//
// INV-4.11 (Safety, ConnectorInfo tag consistency):
//   `EnumerationConnector::info().tag` MUST equal the `ConnectorTag`
//   used in all `ItemKey` constructions by that connector.
//   Violation: identity consistency failures (INV-4.3).
//   Verification: runtime assertion at registration; integration tests.
//
// INV-4.12 (Safety, ConnectorInfo tag uniqueness):
//   No two active connectors in the same deployment may share a
//   `ConnectorTag`.
//   Violation: cross-connector `ItemKey` collisions.
//   Verification: runtime assertion at registration.
//
// INV-4.13 (Liveness, retry convergence):
//   The runtime's retry loop MUST converge (terminate) regardless of
//   `RetryHint` values. A maximum retry count or total timeout must
//   bound all retry sequences.
//   Violation: infinite loops â†’ shard never makes progress.
//   Verification: runtime configuration check; simulation testing.
//
// INV-4.14 (Safety, ReadResult reader lifetime):
//   The `reader` in `ReadResult` MUST remain readable until dropped.
//   The connector MUST NOT invalidate the reader or close underlying
//   connections while a `ReadResult` is live.
//   Violation: I/O errors mid-scan â†’ corrupted scan results.
//   Verification: integration tests with slow reads; stress tests.
//
// INV-4.15 (Safety, CursorInvalidated recovery):
//   When enumeration returns `CursorInvalidated`, the runtime can
//   construct `Cursor { last_key: last_valid_key, token: None }` and
//   restart enumeration. The connector MUST handle a cursor with
//   `token == None` for any valid `last_key` within the shard range.
//   Violation: infinite cursor invalidation loop.
//   Verification: integration tests with token expiration simulation.
//
// INV-4.16 (Safety, enumerate_page re-entrancy):
//   `enumerate_page` takes `&self`, so it MUST be safe to call
//   concurrently for different shards. Internal mutable state (e.g.,
//   connection pools, rate limiters) must use appropriate synchronization.
//   Violation: data races, corrupted internal state.
//   Verification: concurrent shard simulation in deterministic tests.

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- RetryHint --

    #[test]
    fn retry_hint_immediately_should_retry() {
        assert!(RetryHint::Immediately.should_retry());
    }

    #[test]
    fn retry_hint_after_delay_should_retry() {
        assert!(RetryHint::AfterDelay { delay_ms: 1000 }.should_retry());
    }

    #[test]
    fn retry_hint_do_not_retry_should_not_retry() {
        assert!(!RetryHint::DoNotRetry.should_retry());
    }

    // -- EnumerationError --

    #[test]
    fn enumeration_error_rate_limited_display() {
        let e = EnumerationError::RateLimited {
            retry_hint: RetryHint::AfterDelay { delay_ms: 5000 },
            message: "429 Too Many Requests".into(),
        };
        let s = format!("{}", e);
        assert!(s.contains("rate limited"), "got: {s}");
    }

    #[test]
    fn enumeration_error_cursor_invalidated_needs_restart() {
        let e = EnumerationError::CursorInvalidated {
            last_valid_key: Some(b"last-key".to_vec().into_boxed_slice()),
            message: "token expired".into(),
        };
        assert!(e.needs_cursor_restart());
        assert!(e.retry_hint().should_retry());
    }

    #[test]
    fn enumeration_error_budget_exhausted_retryable() {
        let e = EnumerationError::BudgetExhausted {
            exhausted_field: BudgetField::ApiCalls,
        };
        assert!(e.retry_hint().should_retry());
    }

    // -- ReadError --

    #[test]
    fn read_error_not_found_is_permanent() {
        let e = ReadError::ItemNotFound {
            message: "404".into(),
        };
        assert!(!e.retry_hint().should_retry());
    }

    #[test]
    fn read_error_source_error_is_retryable() {
        let e = ReadError::SourceError {
            retry_hint: RetryHint::Immediately,
            message: "connection reset".into(),
        };
        assert!(e.retry_hint().should_retry());
    }

    #[test]
    fn read_error_invalid_ref_needs_re_enumeration() {
        let e = ReadError::InvalidRef {
            message: "pre-signed URL expired".into(),
        };
        assert!(e.needs_re_enumeration());
        assert!(!e.retry_hint().should_retry());
    }

    #[test]
    fn read_error_display() {
        let e = ReadError::PermissionDenied {
            retry_hint: RetryHint::DoNotRetry,
            message: "403 Forbidden".into(),
        };
        let s = format!("{}", e);
        assert!(s.contains("permission denied"), "got: {s}");
    }

    // -- ConnectorInfo --

    #[test]
    fn connector_info_display() {
        let info = ConnectorInfo::new(
            ConnectorTag::from_ascii(b"github"),
            "GitHub App Connector",
            "1.2.3",
        );
        let s = format!("{}", info);
        assert!(s.contains("GitHub App Connector"));
        assert!(s.contains("1.2.3"));
    }

    // -- ReadResult --

    #[test]
    fn read_result_debug_does_not_show_reader() {
        let result = ReadResult {
            reader: Box::new(std::io::Cursor::new(b"secret content")),
            actual_version: None,
            actual_size: Some(14),
        };
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("dyn Read"), "got: {dbg}");
        assert!(!dbg.contains("secret"), "content leaked in Debug: {dbg}");
    }

    // -- Stub connector for trait compilation check --

    /// Minimal test connector that verifies the trait signatures compile.
    struct StubConnector {
        tag: ConnectorTag,
    }

    impl StubConnector {
        fn new() -> Self {
            Self {
                tag: ConnectorTag::from_ascii(b"stub"),
            }
        }
    }

    impl EnumerationConnector for StubConnector {
        fn info(&self) -> ConnectorInfo {
            ConnectorInfo::new(self.tag, "Stub Connector", "0.0.0")
        }

        fn enumerate_page(
            &self,
            _spec: &ShardSpec,
            _cursor: &Cursor,
            _budget: &EnumerationBudget,
        ) -> Result<EnumerationPage, EnumerationError> {
            // Stub: return empty last page.
            Ok(EnumerationPage {
                items: vec![],
                next_cursor: None,
                api_calls_used: 0,
            })
        }
    }

    impl ReadConnector for StubConnector {
        fn info(&self) -> ConnectorInfo {
            ConnectorInfo::new(self.tag, "Stub Connector", "0.0.0")
        }

        fn open_item(
            &self,
            _item_ref: &ItemRef,
            _budget: &ReadBudget,
        ) -> Result<ReadResult, ReadError> {
            // Stub: return empty content.
            Ok(ReadResult {
                reader: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
                actual_version: None,
                actual_size: Some(0),
            })
        }
    }

    #[test]
    fn stub_connector_is_connector() {
        let c = StubConnector::new();
        // Verify Connector trait is automatically satisfied.
        fn assert_connector<T: Connector>(_: &T) {}
        assert_connector(&c);
    }

    #[test]
    fn stub_enumerate_returns_last_page() {
        let c = StubConnector::new();
        let spec = ShardSpec::new(b"a".to_vec(), b"z".to_vec());
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();

        let page = c.enumerate_page(&spec, &cursor, &budget).unwrap();
        assert!(page.is_last_page());
        assert_eq!(page.item_count(), 0);
    }

    #[test]
    fn stub_open_returns_empty_content() {
        let c = StubConnector::new();
        let item_ref = ItemRef::new(b"test-ref".to_vec());
        let budget = ReadBudget::default_for_testing();

        let result = c.open_item(&item_ref, &budget).unwrap();
        assert_eq!(result.actual_size, Some(0));
    }

    // -- Property test stubs --

    // TODO: proptest for EnumerationError retry_hint consistency:
    //   âˆ€ error: error.retry_hint() returns a valid RetryHint
    //
    // TODO: proptest for ReadError retry_hint consistency:
    //   âˆ€ error: error.retry_hint() returns a valid RetryHint
    //
    // TODO: proptest for Connector trait object safety:
    //   Verify Box<dyn EnumerationConnector> and Box<dyn ReadConnector>
    //   are constructible (trait is object-safe).
    //
    // TODO: integration test skeleton for real connector:
    //   enumerate â†’ collect items â†’ open each â†’ verify content readable
}
