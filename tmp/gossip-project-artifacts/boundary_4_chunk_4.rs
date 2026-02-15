//! Boundary â‘£ â€” Connector Contract: Chunk 4 (DRAFT)
//!
//! Deterministic test connector: a fully canned-data implementation of
//! `EnumerationConnector` and `ReadConnector` for use in unit tests,
//! property-based tests, and deterministic simulation.
//!
//! This file is additive to Boundaries â‘ â€“â‘¢ (all chunks) and Boundary â‘£
//! chunks 1â€“3 (value types, traits, runtime bridge).
//!
//! ## Problem Statement
//!
//! Every layer of the runtime needs to exercise connector interactions
//! without real I/O:
//!
//! - **Unit tests**: Verify page validation, cursor extraction, error
//!   mapping, circuit breaker transitions against known outputs.
//! - **Property tests**: Generate random shard ranges and item sets,
//!   verify invariants hold across all combinations.
//! - **Deterministic simulation**: Exercise the full coordination +
//!   connector loop with controlled failures, crashes, and timing.
//!
//! A real connector (GitHub, S3) is unsuitable for these because:
//! - Non-deterministic (API responses vary, rate limits change)
//! - Slow (network I/O dominates test time)
//! - Requires credentials and live infrastructure
//! - Cannot inject failures at precise points
//!
//! ## Design Decisions (locked)
//!
//! D4.30: The test connector is configured via a builder pattern that
//!        accepts a `Vec<TestItem>` â€” a flat list of (path, content)
//!        pairs. Items are sorted by path at build time to match the
//!        ordering invariant (INV-4.4).
//!
//!        **Why**: Flat list is the simplest representation. Sorting
//!        at build time means enumerate_page doesn't need to sort per
//!        call. This mirrors how a real connector would query a sorted
//!        index (e.g., Git tree entries, S3 list-objects-v2).
//!
//! D4.31: Failure injection uses a `FailureScript` â€” an ordered list
//!        of `(call_index, failure)` pairs. Call N returns the scripted
//!        failure instead of real data. This is deterministic and
//!        reproducible from a seed.
//!
//!        **Why**: Scripted failures are strictly more controllable than
//!        random injection. The deterministic simulator can replay any
//!        failure sequence by replaying the script. This matches
//!        FoundationDB's simulation approach where all non-determinism
//!        is captured in a replayable log.
//!
//!        Reference: FoundationDB simulation (Zhou et al., SIGMOD 2021);
//!        TigerBeetle VOPR â€” all I/O outcomes are pre-determined.
//!
//! D4.32: The test connector uses `&self` (shared reference) for both
//!        traits. Internal state (call counter for failure scripts)
//!        uses `RefCell` for single-threaded tests or `AtomicU32` for
//!        concurrent simulation. The default is `RefCell` (simpler,
//!        panics on concurrent access, which is a bug detector).
//!
//!        **Why**: The trait requires `&self`. Interior mutability for
//!        the call counter is the minimal state needed. `RefCell` is
//!        preferred because test connectors are typically used from a
//!        single thread; accidental concurrent use is a test bug that
//!        `RefCell` detects at runtime.
//!
//! D4.33: `TestItem` stores content as `Vec<u8>`, NOT `Box<dyn Read>`.
//!        `open_item` creates a `Cursor<Vec<u8>>` from the stored bytes.
//!
//!        **Why**: Test content is small (kilobytes). Storing as bytes
//!        allows cloning, comparison, and multiple reads from the same
//!        item without reader lifetime issues. The `Cursor<Vec<u8>>`
//!        wrapper satisfies the `Read` trait requirement.

// Assumes all types from prior boundaries and B4 chunks 1â€“3 are in scope.

use std::cell::RefCell;
use std::io::Read;
use core::fmt;

// ============================================================================
// Â§ Chunk 4: Deterministic Test Connector
// ============================================================================

// ---------------------------------------------------------------------------
// Â§4.1 TestItem â€” a canned item with path and content
// ---------------------------------------------------------------------------

/// A single item in the test connector's dataset.
///
/// Represents one file/object/entry that the connector "discovers"
/// during enumeration and "reads" during content retrieval.
#[derive(Clone, Debug)]
pub struct TestItem {
    /// The item's path (key) within the connector's keyspace.
    /// Must be unique within the test dataset.
    pub path: Vec<u8>,

    /// The item's raw content bytes.
    pub content: Vec<u8>,

    /// The item's version. Defaults to a strong version derived
    /// from content hash.
    pub version: VersionId,

    /// Optional content hints.
    pub content_hints: ContentHints,

    /// Human-readable location string.
    pub location_display: String,
}

impl TestItem {
    /// Create a test item with a string path and string content.
    ///
    /// Generates a strong version from the content bytes.
    pub fn new(path: &str, content: &str) -> Self {
        let content_bytes = content.as_bytes().to_vec();
        Self {
            path: path.as_bytes().to_vec(),
            content: content_bytes.clone(),
            version: VersionId::strong_from_bytes(&content_bytes),
            content_hints: ContentHints::text_utf8(),
            location_display: format!("test://{path}"),
        }
    }

    /// Create a test item with raw byte path and content.
    pub fn from_bytes(path: Vec<u8>, content: Vec<u8>) -> Self {
        let version = VersionId::strong_from_bytes(&content);
        let display = String::from_utf8_lossy(&path).into_owned();
        Self {
            path,
            content,
            version,
            content_hints: ContentHints::unknown(),
            location_display: format!("test://{display}"),
        }
    }

    /// Set a weak version (e.g., for testing version-strength logic).
    pub fn with_weak_version(mut self, version_bytes: &[u8]) -> Self {
        self.version = VersionId::weak_from_bytes(version_bytes);
        self
    }

    /// Set a specific strong version (overriding the content-derived default).
    pub fn with_strong_version(mut self, version_bytes: &[u8]) -> Self {
        self.version = VersionId::strong_from_bytes(version_bytes);
        self
    }

    /// Set content hints.
    pub fn with_hints(mut self, hints: ContentHints) -> Self {
        self.content_hints = hints;
        self
    }

    /// Mark as binary content.
    pub fn as_binary(mut self) -> Self {
        self.content_hints = ContentHints::binary();
        self
    }

    /// Convert to a `ScanItem` for a given connector tag.
    ///
    /// This is the core transform: TestItem â†’ ScanItem, matching what
    /// a real connector's enumerate_page would produce.
    fn to_scan_item(&self, tag: ConnectorTag) -> ScanItem {
        let item_key = ItemKey::new(tag, self.path.clone());
        let item_ref = ItemRef::new(self.path.clone()); // Use path as ref for lookup
        let location = ItemLocation::new(&self.location_display);

        ScanItemBuilder::new(item_key, item_ref, self.version.clone(), location)
            .size_hint(self.content.len() as u64)
            .content_hints(self.content_hints.clone())
            .build()
    }
}

// ---------------------------------------------------------------------------
// Â§4.2 ScriptedFailure â€” injectable failure for deterministic testing
// ---------------------------------------------------------------------------

/// A failure that can be injected at a specific call index.
///
/// The test connector maintains a call counter. When the counter
/// matches a scripted failure's `call_index`, the failure is returned
/// instead of real data.
#[derive(Clone, Debug)]
pub enum ScriptedEnumFailure {
    /// Return a rate-limited error with the given delay.
    RateLimit { delay_ms: u32 },

    /// Return an auth failure (permanent).
    AuthPermanent,

    /// Return an auth failure (transient, retry after delay).
    AuthTransient { delay_ms: u32 },

    /// Return a source error (transient).
    SourceTransient,

    /// Return a source error (permanent).
    SourcePermanent,

    /// Invalidate the cursor â€” simulates pagination token expiry.
    CursorInvalidated,

    /// Return a budget-exhausted error.
    BudgetExhausted { field: BudgetField },
}

impl ScriptedEnumFailure {
    /// Convert to an `EnumerationError`.
    fn to_error(&self, last_key: Option<Box<[u8]>>) -> EnumerationError {
        match self {
            Self::RateLimit { delay_ms } => EnumerationError::RateLimited {
                retry_hint: RetryHint::AfterDelay { delay_ms: *delay_ms },
                message: "scripted rate limit".into(),
            },
            Self::AuthPermanent => EnumerationError::AuthFailure {
                retry_hint: RetryHint::DoNotRetry,
                message: "scripted auth failure (permanent)".into(),
            },
            Self::AuthTransient { delay_ms } => EnumerationError::AuthFailure {
                retry_hint: RetryHint::AfterDelay { delay_ms: *delay_ms },
                message: "scripted auth failure (transient)".into(),
            },
            Self::SourceTransient => EnumerationError::SourceError {
                retry_hint: RetryHint::Immediately,
                message: "scripted source error (transient)".into(),
            },
            Self::SourcePermanent => EnumerationError::SourceError {
                retry_hint: RetryHint::DoNotRetry,
                message: "scripted source error (permanent)".into(),
            },
            Self::CursorInvalidated => EnumerationError::CursorInvalidated {
                last_valid_key: last_key,
                message: "scripted cursor invalidation".into(),
            },
            Self::BudgetExhausted { field } => EnumerationError::BudgetExhausted {
                exhausted_field: *field,
            },
        }
    }
}

/// A failure script for read operations.
#[derive(Clone, Debug)]
pub enum ScriptedReadFailure {
    /// Item not found (deleted between enum and read).
    NotFound,

    /// Permission denied (permanent).
    PermissionDenied,

    /// Invalid ref (pre-signed URL expired).
    InvalidRef,

    /// Source error (transient).
    SourceTransient,

    /// Auth failure (permanent).
    AuthPermanent,
}

impl ScriptedReadFailure {
    /// Convert to a `ReadError`.
    fn to_error(&self) -> ReadError {
        match self {
            Self::NotFound => ReadError::ItemNotFound {
                message: "scripted not found".into(),
            },
            Self::PermissionDenied => ReadError::PermissionDenied {
                retry_hint: RetryHint::DoNotRetry,
                message: "scripted permission denied".into(),
            },
            Self::InvalidRef => ReadError::InvalidRef {
                message: "scripted invalid ref".into(),
            },
            Self::SourceTransient => ReadError::SourceError {
                retry_hint: RetryHint::Immediately,
                message: "scripted source error".into(),
            },
            Self::AuthPermanent => ReadError::AuthFailure {
                retry_hint: RetryHint::DoNotRetry,
                message: "scripted auth failure".into(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Â§4.3 TestConnector â€” the deterministic connector implementation
// ---------------------------------------------------------------------------

/// A deterministic connector for testing.
///
/// Pre-loaded with a sorted list of `TestItem`s and optional failure
/// scripts. Implements both `EnumerationConnector` and `ReadConnector`.
///
/// ## Determinism
///
/// Given the same configuration, the connector produces identical
/// output on every run. There is no randomness, no time-dependence,
/// and no I/O. Failure injection is controlled by a script (list of
/// call indices), not by probability.
///
/// ## Thread Safety
///
/// Uses `RefCell` for the call counter. Panics if accessed
/// concurrently â€” this is intentional. Test connectors are designed
/// for single-threaded test execution. Concurrent access is a test
/// setup bug.
///
/// For concurrent simulation, wrap in `Arc<Mutex<..>>` or use
/// `AtomicU32` for the counters. The trait signatures (`&self`)
/// permit this.
///
/// ## Usage
///
/// ```text
///   let connector = TestConnectorBuilder::new("test")
///       .item(TestItem::new("src/main.rs", "fn main() {}"))
///       .item(TestItem::new("secrets.txt", "AWS_KEY=AKIA..."))
///       .enum_failure(2, ScriptedEnumFailure::RateLimit { delay_ms: 1000 })
///       .page_size(10)
///       .build();
///
///   // Use as EnumerationConnector + ReadConnector
///   let page = connector.enumerate_page(&spec, &cursor, &budget)?;
/// ```
pub struct TestConnector {
    /// Connector metadata.
    info: ConnectorInfo,

    /// Items sorted by path. Invariant: no duplicate paths.
    items: Vec<TestItem>,

    /// Maximum items per enumeration page.
    page_size: u32,

    /// Enumeration failure script: (call_index, failure).
    /// Sorted by call_index. Each entry fires at most once.
    enum_failures: Vec<(u32, ScriptedEnumFailure)>,

    /// Read failure script: (path, failure).
    /// When open_item is called for a matching path, the failure fires.
    read_failures: Vec<(Vec<u8>, ScriptedReadFailure)>,

    /// Enumeration call counter (interior mutability for &self).
    enum_call_count: RefCell<u32>,

    /// Read call counter.
    read_call_count: RefCell<u32>,
}

impl TestConnector {
    /// Total number of items in the dataset.
    #[inline]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// The enumeration call counter (for test assertions).
    pub fn enum_calls(&self) -> u32 {
        *self.enum_call_count.borrow()
    }

    /// The read call counter (for test assertions).
    pub fn read_calls(&self) -> u32 {
        *self.read_call_count.borrow()
    }

    /// Reset call counters (for reuse across test phases).
    pub fn reset_counters(&self) {
        *self.enum_call_count.borrow_mut() = 0;
        *self.read_call_count.borrow_mut() = 0;
    }

    /// Find items within a key range [start, end), starting after
    /// the cursor's last_key if present.
    ///
    /// Returns up to `page_size` items.
    fn find_page_items(
        &self,
        spec: &ShardSpec,
        cursor: &Cursor,
        max_items: u32,
    ) -> (Vec<&TestItem>, bool) {
        let effective_max = max_items.min(self.page_size) as usize;

        // Find the starting position based on cursor.
        let start_idx = match &cursor.last_key {
            None => 0,
            Some(last_key) => {
                // Binary search for the first item AFTER last_key.
                let pos = self
                    .items
                    .partition_point(|item| item.path.as_slice() <= last_key.as_ref());
                pos
            }
        };

        // Collect items within the spec's key range.
        let mut result = Vec::with_capacity(effective_max);
        let mut exhausted = true;

        for item in self.items[start_idx..].iter() {
            // Check membership in shard range.
            if !spec.key_range_start.is_empty()
                && item.path.as_slice() < spec.key_range_start.as_ref()
            {
                continue;
            }
            if !spec.key_range_end.is_empty()
                && item.path.as_slice() >= spec.key_range_end.as_ref()
            {
                break; // Items are sorted, so we're past the range.
            }

            if result.len() >= effective_max {
                exhausted = false;
                break;
            }
            result.push(item);
        }

        (result, exhausted)
    }

    /// Check if there's a scripted enumeration failure for the current call.
    fn check_enum_failure(&self, call_idx: u32, cursor: &Cursor) -> Option<EnumerationError> {
        for (trigger_idx, failure) in &self.enum_failures {
            if *trigger_idx == call_idx {
                return Some(failure.to_error(cursor.last_key.clone()));
            }
        }
        None
    }

    /// Check if there's a scripted read failure for the given path.
    fn check_read_failure(&self, path: &[u8]) -> Option<ReadError> {
        for (trigger_path, failure) in &self.read_failures {
            if trigger_path.as_slice() == path {
                return Some(failure.to_error());
            }
        }
        None
    }

    /// Look up a TestItem by path (used by open_item).
    fn find_item_by_ref(&self, item_ref: &ItemRef) -> Option<&TestItem> {
        let ref_bytes = item_ref.as_bytes();
        self.items.iter().find(|item| item.path.as_slice() == ref_bytes)
    }
}

impl fmt::Debug for TestConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestConnector")
            .field("tag", &self.info.tag)
            .field("item_count", &self.items.len())
            .field("page_size", &self.page_size)
            .field("enum_failures", &self.enum_failures.len())
            .field("read_failures", &self.read_failures.len())
            .field("enum_calls", &self.enum_call_count)
            .field("read_calls", &self.read_call_count)
            .finish()
    }
}

impl EnumerationConnector for TestConnector {
    fn info(&self) -> ConnectorInfo {
        self.info.clone()
    }

    fn enumerate_page(
        &self,
        spec: &ShardSpec,
        cursor: &Cursor,
        budget: &EnumerationBudget,
    ) -> Result<EnumerationPage, EnumerationError> {
        let call_idx = {
            let mut count = self.enum_call_count.borrow_mut();
            let idx = *count;
            *count += 1;
            idx
        };

        // Check for scripted failure at this call index.
        if let Some(err) = self.check_enum_failure(call_idx, cursor) {
            return Err(err);
        }

        // Find items for this page.
        let (found_items, exhausted) =
            self.find_page_items(spec, cursor, budget.max_items);

        // Convert TestItems to ScanItems.
        let scan_items: Vec<ScanItem> = found_items
            .iter()
            .map(|ti| ti.to_scan_item(self.info.tag))
            .collect();

        // Compute next cursor.
        let next_cursor = if exhausted {
            None // Last page.
        } else {
            // Cursor points at the last item we returned.
            scan_items.last().map(|item| {
                Cursor::with_last_key(item.item_key.path.to_vec())
            })
        };

        Ok(EnumerationPage {
            items: scan_items,
            next_cursor,
            api_calls_used: 1,
        })
    }
}

impl ReadConnector for TestConnector {
    fn info(&self) -> ConnectorInfo {
        self.info.clone()
    }

    fn open_item(
        &self,
        item_ref: &ItemRef,
        _budget: &ReadBudget,
    ) -> Result<ReadResult, ReadError> {
        {
            let mut count = self.read_call_count.borrow_mut();
            *count += 1;
        }

        let ref_bytes = item_ref.as_bytes();

        // Check for scripted failure.
        if let Some(err) = self.check_read_failure(ref_bytes) {
            return Err(err);
        }

        // Look up the item by path (ItemRef contains path bytes).
        let item = self.find_item_by_ref(item_ref).ok_or_else(|| {
            ReadError::ItemNotFound {
                message: format!(
                    "test item not found for ref ({} bytes)",
                    ref_bytes.len()
                )
                .into(),
            }
        })?;

        Ok(ReadResult {
            reader: Box::new(std::io::Cursor::new(item.content.clone())),
            actual_version: Some(item.version.clone()),
            actual_size: Some(item.content.len() as u64),
        })
    }
}

// ---------------------------------------------------------------------------
// Â§4.4 TestConnectorBuilder â€” fluent construction
// ---------------------------------------------------------------------------

/// Builder for `TestConnector`.
///
/// Accepts items in any order; sorts them by path at build time.
///
/// ## Panics
///
/// `build()` panics if duplicate paths are present.
pub struct TestConnectorBuilder {
    tag: ConnectorTag,
    display_name: String,
    items: Vec<TestItem>,
    page_size: u32,
    enum_failures: Vec<(u32, ScriptedEnumFailure)>,
    read_failures: Vec<(Vec<u8>, ScriptedReadFailure)>,
}

impl TestConnectorBuilder {
    /// Create a builder with the given connector tag string.
    ///
    /// Uses the tag as both the `ConnectorTag` and display name prefix.
    pub fn new(tag: &str) -> Self {
        Self {
            tag: ConnectorTag::from_ascii(tag.as_bytes()),
            display_name: format!("Test Connector ({tag})"),
            items: Vec::new(),
            page_size: 100,
            enum_failures: Vec::new(),
            read_failures: Vec::new(),
        }
    }

    /// Add an item to the dataset.
    pub fn item(mut self, item: TestItem) -> Self {
        self.items.push(item);
        self
    }

    /// Add multiple items.
    pub fn items(mut self, items: impl IntoIterator<Item = TestItem>) -> Self {
        self.items.extend(items);
        self
    }

    /// Set the maximum items per enumeration page.
    pub fn page_size(mut self, size: u32) -> Self {
        assert!(size > 0, "page_size must be > 0");
        self.page_size = size;
        self
    }

    /// Add a scripted enumeration failure at the given call index.
    ///
    /// Call indices are 0-based: the first enumerate_page call is 0.
    pub fn enum_failure(mut self, call_index: u32, failure: ScriptedEnumFailure) -> Self {
        self.enum_failures.push((call_index, failure));
        self
    }

    /// Add a scripted read failure for the given path.
    ///
    /// When `open_item` is called with an `ItemRef` matching this path,
    /// the failure is returned.
    pub fn read_failure(mut self, path: &str, failure: ScriptedReadFailure) -> Self {
        self.read_failures.push((path.as_bytes().to_vec(), failure));
        self
    }

    /// Add a scripted read failure for raw byte path.
    pub fn read_failure_bytes(mut self, path: Vec<u8>, failure: ScriptedReadFailure) -> Self {
        self.read_failures.push((path, failure));
        self
    }

    /// Set a custom display name.
    pub fn display_name(mut self, name: &str) -> Self {
        self.display_name = name.to_string();
        self
    }

    /// Build the `TestConnector`.
    ///
    /// ## Panics
    ///
    /// - If duplicate paths exist in the item set.
    /// - If `page_size` is 0 (already checked in `page_size()`).
    pub fn build(mut self) -> TestConnector {
        // Sort items by path (lexicographic byte order).
        self.items.sort_by(|a, b| a.path.cmp(&b.path));

        // Assert no duplicate paths.
        for window in self.items.windows(2) {
            assert!(
                window[0].path != window[1].path,
                "TestConnector: duplicate path detected: {:?}",
                String::from_utf8_lossy(&window[0].path),
            );
        }

        // Sort enum failures by call index for predictable processing.
        self.enum_failures.sort_by_key(|(idx, _)| *idx);

        TestConnector {
            info: ConnectorInfo::new(self.tag, &self.display_name, "0.0.0-test"),
            items: self.items,
            page_size: self.page_size,
            enum_failures: self.enum_failures,
            read_failures: self.read_failures,
            enum_call_count: RefCell::new(0),
            read_call_count: RefCell::new(0),
        }
    }
}

// ---------------------------------------------------------------------------
// Â§4.5 Convenience constructors for common test scenarios
// ---------------------------------------------------------------------------

/// Create a test connector with N items, paths "item-{i:05}",
/// content "content-{i}".
///
/// Useful for testing pagination, range queries, and budget
/// compliance without hand-crafting items.
pub fn test_connector_with_n_items(tag: &str, n: usize) -> TestConnector {
    let items: Vec<TestItem> = (0..n)
        .map(|i| TestItem::new(&format!("item-{i:05}"), &format!("content-{i}")))
        .collect();
    TestConnectorBuilder::new(tag).items(items).build()
}

/// Create a test connector with N items and a specific page size.
pub fn test_connector_paged(tag: &str, n: usize, page_size: u32) -> TestConnector {
    let items: Vec<TestItem> = (0..n)
        .map(|i| TestItem::new(&format!("item-{i:05}"), &format!("content-{i}")))
        .collect();
    TestConnectorBuilder::new(tag)
        .items(items)
        .page_size(page_size)
        .build()
}

/// Create an empty test connector (no items).
pub fn test_connector_empty(tag: &str) -> TestConnector {
    TestConnectorBuilder::new(tag).build()
}

// ============================================================================
// Â§ Invariant Catalog â€” Boundary â‘£ Chunk 4
// ============================================================================
//
// INV-4.30 (Safety, test connector sorting):
//   Items in TestConnector are sorted by path at build time.
//   enumerate_page returns items in this order, satisfying INV-4.4.
//   Verification: build() asserts sorted + unique; enumerate tests
//   verify ordering.
//
// INV-4.31 (Safety, test connector identity consistency):
//   TestItem.to_scan_item() uses ScanItemBuilder, which asserts
//   identity consistency (INV-4.3) at build time.
//   Verification: any test that calls enumerate_page transitively
//   exercises this assertion.
//
// INV-4.32 (Safety, test connector membership):
//   enumerate_page filters items by [spec.start, spec.end), only
//   returning items within the shard range (INV-4.6).
//   Verification: test with items outside the range, verify excluded.
//
// INV-4.33 (Safety, test connector budget compliance):
//   enumerate_page returns at most min(budget.max_items, page_size)
//   items (INV-4.5).
//   Verification: test with small budget, verify page size respected.
//
// INV-4.34 (Safety, failure script determinism):
//   Given the same configuration and call sequence, TestConnector
//   produces identical outputs. No randomness or time-dependence.
//   Verification: run the same test twice, assert identical results.
//
// INV-4.35 (Safety, no duplicate paths):
//   build() panics if any two items share the same path. Duplicate
//   paths would violate item identity uniqueness.
//   Verification: #[should_panic] test.

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- TestItem construction --

    #[test]
    fn test_item_new_string() {
        let item = TestItem::new("src/main.rs", "fn main() {}");
        assert_eq!(item.path, b"src/main.rs");
        assert_eq!(item.content, b"fn main() {}");
        assert!(item.version.is_strong());
    }

    #[test]
    fn test_item_weak_version() {
        let item = TestItem::new("file.txt", "content")
            .with_weak_version(b"etag-abc");
        assert!(!item.version.is_strong());
    }

    #[test]
    fn test_item_binary_hints() {
        let item = TestItem::new("image.png", "PNG data").as_binary();
        assert!(item.content_hints.is_binary.unwrap_or(false));
    }

    // -- TestConnectorBuilder --

    #[test]
    fn builder_sorts_items() {
        let connector = TestConnectorBuilder::new("test")
            .item(TestItem::new("z-last", "z"))
            .item(TestItem::new("a-first", "a"))
            .item(TestItem::new("m-middle", "m"))
            .build();

        assert_eq!(connector.items[0].path, b"a-first");
        assert_eq!(connector.items[1].path, b"m-middle");
        assert_eq!(connector.items[2].path, b"z-last");
    }

    #[test]
    #[should_panic(expected = "duplicate path")]
    fn builder_rejects_duplicate_paths() {
        TestConnectorBuilder::new("test")
            .item(TestItem::new("dup", "a"))
            .item(TestItem::new("dup", "b"))
            .build();
    }

    // -- Enumeration --

    #[test]
    fn enumerate_empty_connector() {
        let connector = test_connector_empty("test");
        let spec = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();

        let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn enumerate_all_items_single_page() {
        let connector = test_connector_with_n_items("test", 5);
        let spec = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();

        let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
        assert_eq!(page.items.len(), 5);
        assert!(page.next_cursor.is_none()); // All items fit in one page.
    }

    #[test]
    fn enumerate_respects_page_size() {
        let connector = test_connector_paged("test", 10, 3);
        let spec = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();

        let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
        assert_eq!(page.items.len(), 3);
        assert!(page.next_cursor.is_some()); // More items remain.
    }

    #[test]
    fn enumerate_respects_budget_max_items() {
        let connector = test_connector_paged("test", 10, 100);
        let spec = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::new(2, 30_000, 50);

        let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
        assert_eq!(page.items.len(), 2);
        assert!(page.next_cursor.is_some());
    }

    #[test]
    fn enumerate_pagination_covers_all_items() {
        let connector = test_connector_paged("test", 7, 3);
        let spec = ShardSpec::unbounded();
        let budget = EnumerationBudget::default_for_testing();

        let mut cursor = Cursor::initial();
        let mut total_items = 0;
        let mut pages = 0;

        loop {
            let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
            total_items += page.items.len();
            pages += 1;

            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }

        assert_eq!(total_items, 7);
        assert_eq!(pages, 3); // 3 + 3 + 1
    }

    #[test]
    fn enumerate_filters_by_shard_range() {
        let connector = TestConnectorBuilder::new("test")
            .item(TestItem::new("a", "a"))
            .item(TestItem::new("b", "b"))
            .item(TestItem::new("c", "c"))
            .item(TestItem::new("d", "d"))
            .item(TestItem::new("e", "e"))
            .build();

        // Shard covers [b, d) â€” should return b and c only.
        let spec = ShardSpec::with_range(b"b".to_vec(), b"d".to_vec());
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();

        let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].item_key.path.as_ref(), b"b");
        assert_eq!(page.items[1].item_key.path.as_ref(), b"c");
    }

    #[test]
    fn enumerate_cursor_resumes_after_last_key() {
        let connector = test_connector_paged("test", 5, 2);
        let spec = ShardSpec::unbounded();
        let budget = EnumerationBudget::default_for_testing();

        // First page.
        let page1 = connector
            .enumerate_page(&spec, &Cursor::initial(), &budget)
            .unwrap();
        assert_eq!(page1.items.len(), 2);

        // Second page from cursor.
        let cursor = page1.next_cursor.unwrap();
        let page2 = connector
            .enumerate_page(&spec, &cursor, &budget)
            .unwrap();
        assert_eq!(page2.items.len(), 2);

        // Items should not overlap.
        let p1_last = &page1.items[1].item_key.path;
        let p2_first = &page2.items[0].item_key.path;
        assert!(p1_last.as_ref() < p2_first.as_ref());
    }

    #[test]
    fn enumerate_items_are_identity_consistent() {
        let connector = test_connector_with_n_items("test", 5);
        let spec = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();

        let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
        for item in &page.items {
            assert!(
                item.check_identity_consistency(),
                "identity mismatch for path {:?}",
                item.item_key.path,
            );
        }
    }

    // -- Failure injection --

    #[test]
    fn enum_failure_at_call_index() {
        let connector = TestConnectorBuilder::new("test")
            .item(TestItem::new("a", "a"))
            .enum_failure(0, ScriptedEnumFailure::RateLimit { delay_ms: 5000 })
            .build();

        let spec = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();

        // First call (index 0) should fail.
        let err = connector
            .enumerate_page(&spec, &cursor, &budget)
            .unwrap_err();
        assert!(matches!(err, EnumerationError::RateLimited { .. }));

        // Second call (index 1) should succeed.
        let page = connector
            .enumerate_page(&spec, &cursor, &budget)
            .unwrap();
        assert_eq!(page.items.len(), 1);
    }

    #[test]
    fn enum_cursor_invalidation_failure() {
        let connector = TestConnectorBuilder::new("test")
            .item(TestItem::new("a", "a"))
            .enum_failure(0, ScriptedEnumFailure::CursorInvalidated)
            .build();

        let spec = ShardSpec::unbounded();
        let cursor = Cursor::with_last_key(b"prev-key".to_vec());
        let budget = EnumerationBudget::default_for_testing();

        let err = connector
            .enumerate_page(&spec, &cursor, &budget)
            .unwrap_err();
        match err {
            EnumerationError::CursorInvalidated {
                last_valid_key, ..
            } => {
                // Should carry the cursor's last_key.
                assert_eq!(last_valid_key.as_deref(), Some(b"prev-key".as_ref()));
            }
            other => panic!("expected CursorInvalidated, got: {other:?}"),
        }
    }

    // -- Reading --

    #[test]
    fn read_item_returns_content() {
        let connector = TestConnectorBuilder::new("test")
            .item(TestItem::new("file.txt", "hello world"))
            .build();

        let item_ref = ItemRef::new(b"file.txt".to_vec());
        let budget = ReadBudget::default_for_testing();

        let result = connector.open_item(&item_ref, &budget).unwrap();
        assert_eq!(result.actual_size, Some(11));
        assert!(result.actual_version.is_some());

        // Read the content.
        let mut content = String::new();
        let mut reader = result.reader;
        reader.read_to_string(&mut content).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn read_missing_item_returns_not_found() {
        let connector = test_connector_empty("test");
        let item_ref = ItemRef::new(b"nonexistent".to_vec());
        let budget = ReadBudget::default_for_testing();

        let err = connector.open_item(&item_ref, &budget).unwrap_err();
        assert!(matches!(err, ReadError::ItemNotFound { .. }));
    }

    #[test]
    fn read_scripted_failure() {
        let connector = TestConnectorBuilder::new("test")
            .item(TestItem::new("file.txt", "content"))
            .read_failure("file.txt", ScriptedReadFailure::PermissionDenied)
            .build();

        let item_ref = ItemRef::new(b"file.txt".to_vec());
        let budget = ReadBudget::default_for_testing();

        let err = connector.open_item(&item_ref, &budget).unwrap_err();
        assert!(matches!(err, ReadError::PermissionDenied { .. }));
    }

    // -- Call counting --

    #[test]
    fn call_counters_track_invocations() {
        let connector = test_connector_with_n_items("test", 3);
        let spec = ShardSpec::unbounded();
        let budget = EnumerationBudget::default_for_testing();

        assert_eq!(connector.enum_calls(), 0);
        assert_eq!(connector.read_calls(), 0);

        connector
            .enumerate_page(&spec, &Cursor::initial(), &budget)
            .unwrap();
        assert_eq!(connector.enum_calls(), 1);

        let item_ref = ItemRef::new(b"item-00000".to_vec());
        let read_budget = ReadBudget::default_for_testing();
        connector.open_item(&item_ref, &read_budget).unwrap();
        assert_eq!(connector.read_calls(), 1);

        connector.reset_counters();
        assert_eq!(connector.enum_calls(), 0);
        assert_eq!(connector.read_calls(), 0);
    }

    // -- Connector trait satisfaction --

    #[test]
    fn test_connector_is_connector() {
        let c = test_connector_empty("test");
        fn assert_connector<T: Connector>(_: &T) {}
        assert_connector(&c);
    }

    // -- Convenience constructors --

    #[test]
    fn n_items_constructor() {
        let c = test_connector_with_n_items("gen", 100);
        assert_eq!(c.item_count(), 100);
    }

    #[test]
    fn empty_constructor() {
        let c = test_connector_empty("empty");
        assert_eq!(c.item_count(), 0);
    }

    // -- End-to-end: enumerate then read --

    #[test]
    fn end_to_end_enumerate_and_read() {
        let connector = TestConnectorBuilder::new("e2e")
            .item(TestItem::new("a.txt", "alpha"))
            .item(TestItem::new("b.txt", "bravo"))
            .build();

        let spec = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budget = EnumerationBudget::default_for_testing();
        let read_budget = ReadBudget::default_for_testing();

        // Enumerate.
        let page = connector.enumerate_page(&spec, &cursor, &budget).unwrap();
        assert_eq!(page.items.len(), 2);

        // Read each item.
        for item in &page.items {
            let result = connector.open_item(&item.item_ref, &read_budget).unwrap();
            let mut buf = Vec::new();
            result.reader.read_to_end(&mut buf).unwrap();
            assert!(!buf.is_empty());
        }
    }

    // -- Property test stubs --

    // TODO: proptest for pagination completeness:
    //   âˆ€ n, page_size:
    //     iterating enumerate_page until exhaustion yields exactly n items
    //
    // TODO: proptest for ordering across pages:
    //   âˆ€ n, page_size:
    //     concatenating items across all pages produces a sorted sequence
    //
    // TODO: proptest for shard range filtering:
    //   âˆ€ items, [start, end):
    //     all returned items have path âˆˆ [start, end)
    //
    // TODO: proptest for content round-trip:
    //   âˆ€ item:
    //     enumerate â†’ open_item â†’ read == item.content
}
