//! Boundary â‘£ â€” Connector Contract: Chunk 1 (DRAFT)
//!
//! Core value types that connectors produce: the vocabulary shared between
//! the connector layer and the coordination/scanning runtime.
//!
//! This file is additive to Boundaries â‘ â€“â‘¢ (all chunks). It uses
//! `CanonicalBytes`, `ItemKey`, `StableItemId`, `ObjectVersionId`,
//! `ConnectorTag`, `ShardSpec`, and `Cursor` from prior boundaries.
//!
//! ## Problem Statement
//!
//! The scanner instructions Â§2.2 and Â§5.1 require connectors to produce
//! scan items that the runtime can schedule, checkpoint, and deduplicate.
//! The connector contract must:
//!
//! 1. Provide a complete, self-describing scan item with enough metadata
//!    for the runtime to make scheduling and deduplication decisions
//!    WITHOUT reading item content.
//! 2. Separate the "identity" of an item (for dedup) from the "reference"
//!    needed to read it (which may contain transient credentials).
//! 3. Distinguish version strength â€” strong (immutable, content-addressed)
//!    vs. weak (best-effort, may change) â€” so the done-ledger (B5) can
//!    make correct rescan decisions.
//! 4. Provide resource budgets to bound enumeration and reading costs,
//!    enabling backpressure per Â§4.4 of the scanner instructions.
//!
//! ## Design Decisions (locked)
//!
//! D4.1: `VersionId` is an enum with `Strong` and `Weak` variants, NOT
//!       a newtype over `ObjectVersionId`.
//!
//!       **Why**: The done-ledger needs to know whether a version token
//!       is trustworthy for skip-scan decisions. A Git commit SHA is
//!       immutable â€” if the version hasn't changed, the content hasn't
//!       changed, and rescanning is provably unnecessary. A
//!       last-modified timestamp from an HTTP HEAD response is NOT
//!       immutable â€” the server may return stale timestamps, or content
//!       may change without the timestamp updating.
//!
//!       `ObjectVersionId` (B1 chunk 3) is the normalized 32-byte
//!       identity used in finding derivation. `VersionId` wraps it with
//!       a strength tag that the done-ledger inspects.
//!
//!       Reference: Git's content-addressed object model (strong) vs.
//!       HTTP ETag semantics where weak ETags are explicitly marked with
//!       `W/` prefix (RFC 7232 Â§2.3). We adopt the same strong/weak
//!       distinction.
//!
//! D4.2: `ItemRef` is an opaque byte blob, NOT a structured type.
//!
//!       **Why**: The contracts crate cannot anticipate every connector's
//!       credential model. A GitHub connector may need an installation
//!       token + repo coordinates. An S3 connector may need a pre-signed
//!       URL. A local filesystem connector needs just a path.
//!
//!       Making `ItemRef` opaque (like Cursor's `token` field) lets
//!       connectors serialize whatever they need. The runtime stores and
//!       returns it verbatim â€” it never inspects, logs, or displays it.
//!
//!       **Credential safety**: `ItemRef` MUST NOT be logged, displayed,
//!       or persisted beyond the current scan run. It may contain
//!       short-lived credentials. The `StableItemId` and `ItemLocation`
//!       types exist for debugging and display.
//!
//!       Reference: Same pattern as Spanner's opaque restart tokens
//!       (Bacon et al., "Spanner: Becoming a SQL System", 2017) and
//!       our own Cursor `token` field (B2 chunk 1, D2.1).
//!
//! D4.3: `ItemLocation` is display-safe metadata, NOT a credential.
//!
//!       **Why**: Operators need to identify items in dashboards, logs,
//!       and alerts without exposing credentials. `ItemLocation` carries
//!       a human-readable description (e.g., "github.com/org/repo/path.txt")
//!       and an optional URL for click-through. Neither field may contain
//!       authentication tokens.
//!
//!       This is a **separate concern** from `ItemRef` (which enables
//!       reading) and `ItemKey`/`StableItemId` (which enable dedup).
//!
//! D4.4: `ContentHints` is advisory metadata, NOT a guarantee.
//!
//!       **Why**: The runtime and scanner use content hints for
//!       optimization (e.g., skip binary files, choose a parser), but
//!       MUST NOT rely on them for correctness. A connector may report
//!       `media_type: "text/plain"` for a file that is actually binary.
//!       The scanner must handle this gracefully.
//!
//!       This follows the robustness principle: be conservative in what
//!       you produce (connectors SHOULD report accurate hints), liberal
//!       in what you accept (scanners MUST NOT crash on wrong hints).
//!
//!       Reference: Postel's Law (RFC 761); HTTP Content-Type semantics
//!       where the declared type may not match actual content.
//!
//! D4.5: `ScanItem` is the complete, self-describing unit of enumeration
//!       output. It bundles identity, version, content hints, location,
//!       and read reference into a single value.
//!
//!       The runtime destructures a `ScanItem` immediately after
//!       enumeration:
//!       - `item_key` + `stable_item_id` â†’ coordination and dedup
//!       - `version` â†’ done-ledger skip check
//!       - `item_ref` â†’ deferred reading (may be discarded if skip-scan)
//!       - `content_hints` â†’ scanner planning
//!       - `location` â†’ observability
//!       - `size_hint` â†’ resource budgeting
//!
//!       Reference: MapReduce input split metadata (Dean & Ghemawat,
//!       OSDI 2004) â€” each split carries enough information for the
//!       framework to schedule and track it without reading content.
//!
//! D4.6: Budgets are explicit, bounded resource envelopes. Every
//!       connector operation receives a budget that caps:
//!       - Wall-clock time (for lease renewal planning)
//!       - Items/bytes produced (for backpressure)
//!       - API calls made (for rate-limit compliance)
//!
//!       Connectors MUST respect budgets and return partial results
//!       rather than exceeding them. The coordinator re-issues work
//!       with fresh budgets on the next cycle.
//!
//!       Reference: Reactive Streams backpressure (reactive-streams.org);
//!       TCP flow control (Jacobson, "Congestion Avoidance and Control",
//!       1988); Â§4.4 of scanner instructions.
//!
//! D4.7: Budget fields use `u32` for item counts and `u64` for byte
//!       counts. These are deliberately NOT `usize` â€” budgets must be
//!       serializable and platform-independent. `u32` items (4 billion)
//!       and `u64` bytes (18 EiB) are far beyond any single page.
//!
//!       Reference: Protocol Buffers use fixed-width integer types for
//!       cross-platform compatibility (Kleppmann, DDIA ch. 4).

// Assumes all types from Boundaries â‘ â€“â‘¢ are in scope:
// use crate::{
//     CanonicalBytes, Hasher,
//     ConnectorTag, ItemKey, StableItemId, ObjectVersionId,
//     ShardSpec, Cursor,
//     domain_hasher, finalize_32,
// };

use core::fmt;

// ============================================================================
// Â§ Chunk 1: Core Connector Value Types
// ============================================================================

// ---------------------------------------------------------------------------
// Â§1.1 VersionId â€” version token with strength classification
// ---------------------------------------------------------------------------

/// Version identity with an explicit strength classification.
///
/// Connectors produce `VersionId` to tell the runtime how much to trust
/// the version token for skip-scan decisions.
///
/// ## Variants
///
/// **`Strong(ObjectVersionId)`**: The version token is immutable and
/// content-addressed. If two scans of the same item produce the same
/// strong version, the content is identical, and the second scan can be
/// safely skipped.
///
/// Examples:
/// - Git commit SHA for a file (the commit + tree path uniquely pins content)
/// - S3 object with versioning enabled (version ID is immutable)
/// - Content hash of a file
///
/// **`Weak(ObjectVersionId)`**: The version token is best-effort. It
/// MAY change even if content is unchanged (e.g., metadata-only update),
/// or it MAY stay the same even if content changed (e.g., mutable S3
/// object overwritten without versioning). The done-ledger MUST NOT
/// use weak versions for skip-scan â€” it must treat them as "always
/// potentially changed."
///
/// Examples:
/// - HTTP Last-Modified header (second-granularity, can be wrong)
/// - S3 ETag on a multipart upload (not a content hash)
/// - Confluence page version number (monotonic but may skip values)
///
/// ## Invariants
///
/// **Safety (determinism)**: The same connector, given the same source
/// state, MUST produce the same `VersionId` variant and value. The
/// variant (Strong/Weak) is a property of the connector's version
/// model, not of individual items.
///
/// **Safety (strength honesty)**: A connector MUST NOT mark a version
/// as `Strong` unless it can guarantee content immutability. It is
/// always safe to mark a version as `Weak` â€” this only costs
/// unnecessary rescans, not correctness.
///
/// ## Verification Strategy
///
/// Integration tests per connector: verify that `Strong` versions
/// are genuinely immutable by fetching content twice with the same
/// version and asserting byte-for-byte identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum VersionId {
    /// Immutable, content-addressed version. Safe for skip-scan.
    Strong(ObjectVersionId),
    /// Best-effort version. NOT safe for skip-scan alone.
    Weak(ObjectVersionId),
}

impl VersionId {
    /// Extract the inner `ObjectVersionId` regardless of strength.
    #[inline]
    pub fn object_version(&self) -> &ObjectVersionId {
        match self {
            Self::Strong(v) | Self::Weak(v) => v,
        }
    }

    /// Returns `true` if the version is strong (immutable).
    #[inline]
    pub fn is_strong(&self) -> bool {
        matches!(self, Self::Strong(_))
    }

    /// Returns `true` if the version is weak (best-effort).
    #[inline]
    pub fn is_weak(&self) -> bool {
        matches!(self, Self::Weak(_))
    }

    /// Construct a strong version from raw version bytes.
    ///
    /// Convenience: hashes `bytes` through `ObjectVersionId::from_version_bytes`.
    pub fn strong_from_bytes(bytes: &[u8]) -> Self {
        Self::Strong(ObjectVersionId::from_version_bytes(bytes))
    }

    /// Construct a weak version from raw version bytes.
    pub fn weak_from_bytes(bytes: &[u8]) -> Self {
        Self::Weak(ObjectVersionId::from_version_bytes(bytes))
    }
}

impl CanonicalBytes for VersionId {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        // Discriminant byte: 0x01 = Strong, 0x02 = Weak.
        // Using non-zero values so that accidental zero-bytes don't
        // collide with valid discriminants.
        match self {
            Self::Strong(v) => {
                h.update(&[0x01]);
                v.write_canonical(h);
            }
            Self::Weak(v) => {
                h.update(&[0x02]);
                v.write_canonical(h);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Â§1.2 ItemRef â€” opaque, credential-bearing read reference
// ---------------------------------------------------------------------------

/// Opaque reference enabling content retrieval for a scan item.
///
/// `ItemRef` carries whatever the connector needs to open and read
/// the item's content: pre-signed URLs, installation tokens, file
/// paths, API coordinates, etc.
///
/// ## Credential Safety
///
/// `ItemRef` is the ONLY type in the connector contract that may
/// contain credentials. It is subject to strict handling rules:
///
/// 1. **Never log**: `Debug` is redacted. `Display` is not implemented.
/// 2. **Never persist**: `ItemRef` lives only in memory during the
///    current scan cycle. If a shard is checkpointed and resumed,
///    the connector re-enumerates and produces fresh `ItemRef` values.
/// 3. **Never display**: Use `ItemLocation` for operator-visible identity.
/// 4. **Never send cross-worker**: `ItemRef` is valid only on the
///    worker that produced it (credentials may be worker-scoped).
///
/// ## Structure
///
/// The inner bytes are completely opaque to the contracts crate and
/// the runtime. Only the connector that produced an `ItemRef` can
/// interpret it.
///
/// ## Invariants
///
/// **Safety (opacity)**: The runtime MUST NOT inspect, modify, or
/// make assumptions about the contents of `ItemRef`.
///
/// **Safety (scope)**: An `ItemRef` is valid only for the scan cycle
/// in which it was produced. Connectors MAY embed time-limited
/// credentials (e.g., pre-signed URLs with 15-minute expiry).
///
/// **Liveness**: A valid `ItemRef` MUST be usable to open and read
/// the item's content at least once within the current scan cycle,
/// subject to the connector's credential lifetime.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemRef(Box<[u8]>);

impl ItemRef {
    /// Construct from raw bytes.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is empty.
    pub fn new(bytes: Vec<u8>) -> Self {
        assert!(!bytes.is_empty(), "ItemRef must not be empty");
        Self(bytes.into_boxed_slice())
    }

    /// Access the raw bytes. Connector-internal use only.
    ///
    /// Callers MUST NOT log, display, or persist the returned bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Byte length of the reference (for resource accounting, not content).
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for ItemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately redacted â€” may contain credentials.
        write!(f, "ItemRef(<{} bytes, redacted>)", self.0.len())
    }
}

// No Display impl â€” intentionally omitted for credential safety.
// No CanonicalBytes impl â€” ItemRef does not participate in hashing.

// ---------------------------------------------------------------------------
// Â§1.3 ContentHints â€” advisory metadata for scanner optimization
// ---------------------------------------------------------------------------

/// Advisory metadata about an item's content.
///
/// Connectors SHOULD populate these fields accurately, but the scanner
/// MUST NOT rely on them for correctness. They enable optimizations:
///
/// - Skip binary files in text-only scan rules
/// - Select appropriate parsers based on media type
/// - Pre-allocate buffers based on encoding hints
///
/// ## Invariants
///
/// **Safety (non-binding)**: No correctness property may depend on
/// `ContentHints` values. They are optimization hints only.
///
/// **Liveness (best-effort)**: Connectors SHOULD populate hints when
/// the information is cheaply available (e.g., from HTTP headers,
/// file extensions, API metadata). Connectors SHOULD NOT make
/// additional API calls solely to populate hints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentHints {
    /// IANA media type, e.g., `"text/plain"`, `"application/json"`.
    ///
    /// `None` means unknown. The scanner should treat unknown media
    /// types as potentially scannable (conservative default).
    pub media_type: Option<Box<str>>,

    /// Character encoding, e.g., `"utf-8"`, `"iso-8859-1"`.
    ///
    /// `None` means unknown. The scanner should attempt UTF-8 first
    /// and fall back to binary scanning if decoding fails.
    pub encoding: Option<Box<str>>,

    /// Whether the content is known to be binary (non-text).
    ///
    /// `Some(true)` = definitely binary (e.g., images, compiled objects).
    /// `Some(false)` = definitely text.
    /// `None` = unknown, scanner should probe.
    ///
    /// This is a separate signal from `media_type` because some
    /// connectors can cheaply detect binary content (e.g., GitHub's
    /// `is_binary` flag) without knowing the specific media type.
    pub is_binary: Option<bool>,
}

impl ContentHints {
    /// Create hints with all fields unknown.
    #[inline]
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Create hints for a text file with the given media type.
    pub fn text(media_type: &str) -> Self {
        Self {
            media_type: Some(media_type.into()),
            encoding: Some("utf-8".into()),
            is_binary: Some(false),
        }
    }

    /// Create hints for a binary file with the given media type.
    pub fn binary(media_type: &str) -> Self {
        Self {
            media_type: Some(media_type.into()),
            encoding: None,
            is_binary: Some(true),
        }
    }

    /// Returns `true` if the content is known to be binary.
    #[inline]
    pub fn known_binary(&self) -> bool {
        self.is_binary == Some(true)
    }

    /// Returns `true` if the content is known to be text.
    #[inline]
    pub fn known_text(&self) -> bool {
        self.is_binary == Some(false)
    }
}

// ---------------------------------------------------------------------------
// Â§1.4 ItemLocation â€” display-safe, credential-free item description
// ---------------------------------------------------------------------------

/// Human-readable location of a scan item for observability.
///
/// `ItemLocation` is the display-safe counterpart to `ItemRef`. It
/// carries enough information for operators to identify an item in
/// dashboards, logs, and alerts, but MUST NOT contain credentials.
///
/// ## Fields
///
/// - `display`: A human-readable string identifying the item.
///   Examples: `"github.com/org/repo/src/config.yml"`,
///   `"s3://bucket/prefix/key.json"`,
///   `"confluence/SPACE/Page Title"`.
///
/// - `url`: An optional click-through URL for the item. This is
///   the public URL (e.g., GitHub blob URL), NOT a pre-signed or
///   authenticated URL. `None` if no public URL exists.
///
/// ## Invariants
///
/// **Safety (credential-free)**: Neither `display` nor `url` may
/// contain authentication tokens, API keys, or other secrets.
/// Connectors MUST strip credentials before constructing.
///
/// **Safety (stability)**: `display` SHOULD be stable across scans
/// for the same item (same path â†’ same display string). This is
/// not a hard requirement because display strings don't participate
/// in dedup â€” `StableItemId` handles that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemLocation {
    /// Human-readable description. Always non-empty.
    pub display: Box<str>,
    /// Optional public URL for click-through. Must not contain credentials.
    pub url: Option<Box<str>>,
}

impl ItemLocation {
    /// Construct with a display string and no URL.
    ///
    /// # Panics
    ///
    /// Panics if `display` is empty.
    pub fn new(display: &str) -> Self {
        assert!(!display.is_empty(), "ItemLocation display must not be empty");
        Self {
            display: display.into(),
            url: None,
        }
    }

    /// Construct with both display string and URL.
    ///
    /// # Panics
    ///
    /// Panics if `display` is empty.
    pub fn with_url(display: &str, url: &str) -> Self {
        assert!(!display.is_empty(), "ItemLocation display must not be empty");
        Self {
            display: display.into(),
            url: Some(url.into()),
        }
    }
}

impl fmt::Display for ItemLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display)
    }
}

// ---------------------------------------------------------------------------
// Â§1.5 ScanItem â€” complete enumeration output unit
// ---------------------------------------------------------------------------

/// A single scannable item produced by connector enumeration.
///
/// `ScanItem` is the fundamental unit of work flowing from the
/// enumeration phase to the scanning phase. It carries everything
/// the runtime needs to schedule, deduplicate, and track the item
/// WITHOUT reading its content.
///
/// ## Lifecycle
///
/// ```text
///   Connector                     Runtime
///   â”€â”€â”€â”€â”€â”€â”€â”€â”€                     â”€â”€â”€â”€â”€â”€â”€
///   enumerate_page(spec, cursor)
///       â”‚
///       â”œâ”€â”€â–º ScanItem { key, ref, version, hints, location, size }
///       â”‚
///       â”‚    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
///       â”‚    â”‚ Runtime destructures:                â”‚
///       â”‚    â”‚  â€¢ key + stable_id â†’ dedup check     â”‚
///       â”‚    â”‚  â€¢ version â†’ done-ledger skip check  â”‚
///       â”‚    â”‚  â€¢ size_hint â†’ budget accounting     â”‚
///       â”‚    â”‚  â€¢ item_ref â†’ deferred read (or skip)â”‚
///       â”‚    â”‚  â€¢ content_hints â†’ scanner planning  â”‚
///       â”‚    â”‚  â€¢ location â†’ tracing / dashboards   â”‚
///       â”‚    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// ## Invariants
///
/// **Safety (membership)**: A `ScanItem` produced during enumeration
/// of shard `S` MUST have `item_key` within `S`'s key range
/// `[start, end)` (lexicographic comparison on `item_key.path`).
/// The coordinator validates this via cursor bounds checking (B2).
///
/// **Safety (identity consistency)**: `stable_item_id` MUST equal
/// `item_key.stable_id()`. The runtime asserts this on receipt.
///
/// **Safety (ordered output)**: Within a single `enumerate_page` call,
/// items MUST be returned in non-decreasing `item_key` order
/// (lexicographic on the full `ItemKey` canonical encoding).
/// This enables the cursor's `last_key` to be set to the last
/// item's key for monotonicity.
///
/// ## Verification Strategy
///
/// - Property test: `stable_item_id == item_key.stable_id()` for all items.
/// - Property test: items within a page are sorted by key.
/// - Integration test: all item keys fall within the shard's key range.
#[derive(Clone, Debug)]
pub struct ScanItem {
    /// Logical identity of the item (connector tag + path).
    pub item_key: ItemKey,

    /// Pre-computed fixed-width identity. Must equal `item_key.stable_id()`.
    pub stable_item_id: StableItemId,

    /// Opaque reference for reading the item's content.
    pub item_ref: ItemRef,

    /// Version identity with strength classification.
    pub version: VersionId,

    /// Advisory size of the item's content in bytes. `None` if unknown.
    ///
    /// Used for budget accounting and buffer pre-allocation. The actual
    /// content may be larger or smaller â€” this is a hint, not a promise.
    pub size_hint: Option<u64>,

    /// Advisory content metadata (media type, encoding, binary flag).
    pub content_hints: ContentHints,

    /// Human-readable, credential-free location for observability.
    pub location: ItemLocation,
}

impl ScanItem {
    /// Validate the identity consistency invariant.
    ///
    /// Returns `true` if `stable_item_id` matches the deterministic
    /// derivation from `item_key`. This SHOULD be asserted on
    /// construction and on receipt by the runtime.
    #[inline]
    pub fn check_identity_consistency(&self) -> bool {
        self.stable_item_id == self.item_key.stable_id()
    }

    /// Assert identity consistency. Panics on mismatch.
    ///
    /// Call this at construction time (connector side) and at receipt
    /// time (runtime side) for defense-in-depth.
    ///
    /// Reference: Tiger Style â€” "assert at every boundary."
    #[inline]
    pub fn assert_identity_consistency(&self) {
        assert!(
            self.check_identity_consistency(),
            "ScanItem identity mismatch: stable_item_id does not match item_key.stable_id(). \
             item_key: {:?}, got stable_item_id: {:?}, expected: {:?}",
            self.item_key,
            self.stable_item_id,
            self.item_key.stable_id(),
        );
    }
}

// ---------------------------------------------------------------------------
// Â§1.6 ScanItemBuilder â€” validated construction
// ---------------------------------------------------------------------------

/// Builder for `ScanItem` with validation at construction time.
///
/// Ensures identity consistency is checked before the item enters
/// the system. This is the recommended construction path.
pub struct ScanItemBuilder {
    item_key: ItemKey,
    item_ref: ItemRef,
    version: VersionId,
    size_hint: Option<u64>,
    content_hints: ContentHints,
    location: ItemLocation,
}

impl ScanItemBuilder {
    /// Start building a scan item with the required fields.
    pub fn new(
        item_key: ItemKey,
        item_ref: ItemRef,
        version: VersionId,
        location: ItemLocation,
    ) -> Self {
        Self {
            item_key,
            item_ref,
            version,
            size_hint: None,
            content_hints: ContentHints::unknown(),
            location,
        }
    }

    /// Set the size hint.
    pub fn size_hint(mut self, size: u64) -> Self {
        self.size_hint = Some(size);
        self
    }

    /// Set content hints.
    pub fn content_hints(mut self, hints: ContentHints) -> Self {
        self.content_hints = hints;
        self
    }

    /// Build the `ScanItem`, computing and asserting identity consistency.
    ///
    /// # Panics
    ///
    /// Panics if `item_key.stable_id()` computation fails (should never
    /// happen for a valid `ItemKey`).
    pub fn build(self) -> ScanItem {
        let stable_item_id = self.item_key.stable_id();

        let item = ScanItem {
            item_key: self.item_key,
            stable_item_id,
            item_ref: self.item_ref,
            version: self.version,
            size_hint: self.size_hint,
            content_hints: self.content_hints,
            location: self.location,
        };

        // Tiger Style: assert at construction boundary.
        item.assert_identity_consistency();
        item
    }
}

// ---------------------------------------------------------------------------
// Â§1.7 EnumerationBudget â€” resource envelope for enumerate_page
// ---------------------------------------------------------------------------

/// Resource budget for a single `enumerate_page` call.
///
/// The connector MUST respect all budget fields and return partial
/// results rather than exceeding any limit. The coordinator issues
/// fresh budgets on each call; connectors do not carry budgets
/// across calls.
///
/// ## Design Rationale
///
/// Budgets serve multiple purposes:
///
/// 1. **Backpressure**: Prevent connectors from overwhelming the
///    runtime with more items than it can process. The coordinator
///    adjusts `max_items` based on pipeline pressure.
///    Reference: Reactive Streams backpressure (reactive-streams.org).
///
/// 2. **Lease alignment**: `max_wall_time` ensures the connector
///    returns before the shard's lease expires, giving the worker
///    time to checkpoint. The coordinator computes this as
///    `lease_remaining - checkpoint_margin`.
///    Reference: Gray & Cheriton, "Leases" (SOSP 1989).
///
/// 3. **Rate limiting**: `max_api_calls` prevents connectors from
///    exhausting API quotas. The coordinator tracks quota usage
///    across workers and distributes allowances.
///
/// ## Invariants
///
/// **Safety (bounded)**: The connector MUST NOT exceed any budget
/// field. If it reaches a limit, it stops and returns what it has.
///
/// **Safety (non-zero)**: All budget fields are non-zero at
/// construction. A zero budget means "do nothing" and should not
/// be issued.
///
/// **Liveness (progress)**: Under a non-zero budget, the connector
/// MUST make progress â€” either return at least one item or report
/// an error. Returning zero items with a non-error status is a
/// liveness violation (distinguishable from "end of shard" via the
/// cursor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumerationBudget {
    /// Maximum number of items to return in this page.
    ///
    /// The connector MUST return at most this many items. It MAY
    /// return fewer if the shard is exhausted or another budget
    /// limit is reached first.
    pub max_items: u32,

    /// Maximum wall-clock time (in milliseconds) for this call.
    ///
    /// The connector SHOULD return before this duration elapses,
    /// even if fewer than `max_items` have been produced. This
    /// ensures the worker has time to checkpoint before its lease
    /// expires.
    ///
    /// Note: This is wall-clock guidance, not a hard interrupt.
    /// Connectors should check elapsed time between API calls
    /// and stop if approaching the limit.
    pub max_wall_time_ms: u32,

    /// Maximum number of external API calls for this page.
    ///
    /// For connectors backed by rate-limited APIs (GitHub, GitLab,
    /// Confluence), this caps the number of requests. A connector
    /// that needs 1 API call per N items should compute its effective
    /// item limit as `min(max_items, max_api_calls * N)`.
    pub max_api_calls: u32,
}

impl EnumerationBudget {
    /// Construct a budget with validated non-zero fields.
    ///
    /// # Panics
    ///
    /// Panics if any field is zero.
    pub fn new(max_items: u32, max_wall_time_ms: u32, max_api_calls: u32) -> Self {
        assert!(max_items > 0, "max_items must be > 0");
        assert!(max_wall_time_ms > 0, "max_wall_time_ms must be > 0");
        assert!(max_api_calls > 0, "max_api_calls must be > 0");

        Self {
            max_items,
            max_wall_time_ms,
            max_api_calls,
        }
    }

    /// A generous default budget for testing and simple scenarios.
    ///
    /// Production code should compute budgets from lease state and
    /// pipeline pressure, not use this default.
    pub fn default_for_testing() -> Self {
        Self {
            max_items: 1000,
            max_wall_time_ms: 30_000,
            max_api_calls: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// Â§1.8 ReadBudget â€” resource envelope for content reading
// ---------------------------------------------------------------------------

/// Resource budget for a single `open` + read cycle.
///
/// Similar to `EnumerationBudget` but tailored to content retrieval:
/// it caps bytes read and download time rather than items enumerated.
///
/// ## Invariants
///
/// **Safety (bounded)**: The connector MUST NOT read more than
/// `max_bytes` from the content stream. Truncation at the limit
/// is acceptable â€” the scanner handles partial content.
///
/// **Safety (non-zero)**: All fields are non-zero at construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadBudget {
    /// Maximum bytes to read from the item's content.
    ///
    /// If the item is larger than this, the connector returns a
    /// truncated stream. The scanner is responsible for handling
    /// truncation (e.g., by scanning what it got and logging a
    /// warning for the remainder).
    pub max_bytes: u64,

    /// Maximum wall-clock time (in milliseconds) for the read.
    pub max_wall_time_ms: u32,
}

impl ReadBudget {
    /// Construct a budget with validated non-zero fields.
    ///
    /// # Panics
    ///
    /// Panics if any field is zero.
    pub fn new(max_bytes: u64, max_wall_time_ms: u32) -> Self {
        assert!(max_bytes > 0, "max_bytes must be > 0");
        assert!(max_wall_time_ms > 0, "max_wall_time_ms must be > 0");

        Self {
            max_bytes,
            max_wall_time_ms,
        }
    }

    /// A generous default budget for testing.
    pub fn default_for_testing() -> Self {
        Self {
            max_bytes: 100 * 1024 * 1024, // 100 MiB
            max_wall_time_ms: 60_000,      // 60 seconds
        }
    }
}

// ---------------------------------------------------------------------------
// Â§1.9 EnumerationPage â€” result of a single enumerate_page call
// ---------------------------------------------------------------------------

/// Result of a single `enumerate_page` call.
///
/// Contains the items produced and the cursor state for resumption.
///
/// ## Invariants
///
/// **Safety (ordered)**: Items are in non-decreasing `item_key` order.
///
/// **Safety (bounded)**: `items.len() <= budget.max_items` (where
/// `budget` was the input to the call that produced this page).
///
/// **Safety (membership)**: All `item_key` values are within the
/// shard's `[start, end)` range. The coordinator re-validates this
/// via cursor bounds checking.
///
/// **Liveness (termination)**: If `next_cursor` is `None`, the shard
/// is exhausted â€” no more items exist in the key range. The
/// coordinator transitions the shard to Done.
///
/// If `next_cursor` is `Some(cursor)`, more items may exist and the
/// coordinator should re-invoke `enumerate_page` with the new cursor.
///
/// ## Budget Accounting
///
/// `api_calls_used` reports the actual API calls consumed, enabling
/// the coordinator to track global rate-limit budgets.
#[derive(Clone, Debug)]
pub struct EnumerationPage {
    /// Items produced in this page, sorted by `item_key`.
    pub items: Vec<ScanItem>,

    /// Cursor for the next page, or `None` if the shard is exhausted.
    ///
    /// When `Some`, the cursor's `last_key` MUST equal the last item's
    /// key (or be strictly greater). When `None`, no more items remain.
    pub next_cursor: Option<Cursor>,

    /// Actual API calls consumed during this enumeration call.
    ///
    /// Used by the coordinator for rate-limit tracking. Connectors
    /// that don't make external API calls should report 0.
    pub api_calls_used: u32,
}

impl EnumerationPage {
    /// Returns `true` if this is the last page (shard exhausted).
    #[inline]
    pub fn is_last_page(&self) -> bool {
        self.next_cursor.is_none()
    }

    /// Returns the number of items in this page.
    #[inline]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Validate ordering invariant: items are sorted by key.
    ///
    /// Returns `true` if items are in non-decreasing order.
    /// The coordinator SHOULD assert this on receipt.
    pub fn check_ordering(&self) -> bool {
        self.items.windows(2).all(|pair| {
            let a = &pair[0].item_key;
            let b = &pair[1].item_key;
            // Compare connector tag first, then path.
            (a.connector, &a.path) <= (b.connector, &b.path)
        })
    }

    /// Assert ordering invariant. Panics on violation.
    pub fn assert_ordering(&self) {
        assert!(
            self.check_ordering(),
            "EnumerationPage items are not in non-decreasing key order"
        );
    }

    /// Validate identity consistency for all items in the page.
    pub fn assert_all_identity_consistent(&self) {
        for (i, item) in self.items.iter().enumerate() {
            assert!(
                item.check_identity_consistency(),
                "ScanItem at index {} has inconsistent identity: \
                 item_key: {:?}, stable_item_id: {:?}, expected: {:?}",
                i,
                item.item_key,
                item.stable_item_id,
                item.item_key.stable_id(),
            );
        }
    }
}

// ============================================================================
// Â§ Invariant Catalog â€” Boundary â‘£ Chunk 1
// ============================================================================
//
// INV-4.1 (Safety, version-strength honesty):
//   A connector MUST NOT produce `VersionId::Strong(v)` unless it can
//   guarantee that two items with the same `v` have byte-identical content.
//   Violation: false skip-scans â†’ missed secrets.
//   Verification: per-connector integration tests that fetch content
//   twice with the same strong version and compare bytes.
//
// INV-4.2 (Safety, ItemRef credential isolation):
//   `ItemRef` MUST NOT be logged, persisted, or transmitted across trust
//   boundaries. It MAY contain short-lived credentials.
//   Violation: credential leakage.
//   Verification: grep audit for ItemRef usage; Debug output is redacted.
//
// INV-4.3 (Safety, identity consistency):
//   For every `ScanItem`, `stable_item_id == item_key.stable_id()`.
//   Violation: dedup failures â†’ double-processing or missed items.
//   Verification: `assert_identity_consistency()` at construction and
//   receipt; proptest for arbitrary ItemKey values.
//
// INV-4.4 (Safety, enumeration ordering):
//   Items within an `EnumerationPage` are in non-decreasing `item_key` order.
//   Violation: cursor monotonicity violations â†’ progress regression.
//   Verification: `assert_ordering()` at receipt; proptest for page
//   construction from sorted item lists.
//
// INV-4.5 (Safety, budget compliance):
//   `EnumerationPage.items.len() <= budget.max_items`.
//   Violation: backpressure failure â†’ runtime overload.
//   Verification: runtime assertion at receipt.
//
// INV-4.6 (Safety, membership):
//   All `item_key` paths in an EnumerationPage fall within the shard's
//   `[start, end)` key range.
//   Violation: items processed by wrong shard â†’ dedup/coverage failures.
//   Verification: cursor bounds checking (B2, D2.4).
//
// INV-4.7 (Liveness, progress):
//   Under a non-zero budget, `enumerate_page` returns at least one item
//   OR `next_cursor == None` (shard exhausted) OR an error.
//   Zero items + Some(cursor) + no error = liveness violation.
//   Verification: runtime assertion at receipt.
//
// INV-4.8 (Safety, budget non-zero):
//   Budget fields are always > 0 at construction.
//   Violation: meaningless "do nothing" budget.
//   Verification: panic in constructors.
//
// INV-4.9 (Safety, ItemLocation credential-free):
//   Neither `ItemLocation.display` nor `ItemLocation.url` contains
//   authentication tokens or secrets.
//   Verification: connector-level review; integration tests that
//   assert display strings match known-safe patterns.

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --

    fn test_connector() -> ConnectorTag {
        ConnectorTag::from_ascii(b"test")
    }

    fn test_item_key(path: &[u8]) -> ItemKey {
        ItemKey::new(test_connector(), path.to_vec())
    }

    fn test_version() -> VersionId {
        VersionId::strong_from_bytes(b"v1-commit-abc123")
    }

    fn test_item_ref() -> ItemRef {
        ItemRef::new(b"ref-data-not-a-credential".to_vec())
    }

    fn test_location() -> ItemLocation {
        ItemLocation::new("test/repo/file.txt")
    }

    fn test_scan_item(path: &[u8]) -> ScanItem {
        ScanItemBuilder::new(
            test_item_key(path),
            test_item_ref(),
            test_version(),
            test_location(),
        )
        .build()
    }

    // -- VersionId --

    #[test]
    fn version_id_strong_is_strong() {
        let v = VersionId::strong_from_bytes(b"abc");
        assert!(v.is_strong());
        assert!(!v.is_weak());
    }

    #[test]
    fn version_id_weak_is_weak() {
        let v = VersionId::weak_from_bytes(b"abc");
        assert!(v.is_weak());
        assert!(!v.is_strong());
    }

    #[test]
    fn version_id_same_bytes_different_strength_differ() {
        let strong = VersionId::strong_from_bytes(b"same");
        let weak = VersionId::weak_from_bytes(b"same");
        // Same ObjectVersionId inside, but VersionId itself differs.
        assert_eq!(strong.object_version(), weak.object_version());
        assert_ne!(strong, weak);
    }

    #[test]
    fn version_id_canonical_bytes_differ_by_strength() {
        let strong = VersionId::strong_from_bytes(b"same");
        let weak = VersionId::weak_from_bytes(b"same");

        let hash = |v: &VersionId| -> [u8; 32] {
            let mut h = blake3::Hasher::new();
            v.write_canonical(&mut h);
            let mut out = [0u8; 32];
            h.finalize_xof().fill(&mut out);
            out
        };

        assert_ne!(hash(&strong), hash(&weak));
    }

    // -- ItemRef --

    #[test]
    fn item_ref_debug_redacted() {
        let r = ItemRef::new(b"secret-token-12345".to_vec());
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("redacted"), "got: {dbg}");
        assert!(!dbg.contains("secret"), "credential leaked in Debug: {dbg}");
    }

    #[test]
    fn item_ref_len() {
        let r = ItemRef::new(vec![1, 2, 3]);
        assert_eq!(r.len(), 3);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn item_ref_empty_panics() {
        ItemRef::new(vec![]);
    }

    // -- ContentHints --

    #[test]
    fn content_hints_unknown_defaults() {
        let h = ContentHints::unknown();
        assert!(h.media_type.is_none());
        assert!(h.encoding.is_none());
        assert!(h.is_binary.is_none());
        assert!(!h.known_binary());
        assert!(!h.known_text());
    }

    #[test]
    fn content_hints_text() {
        let h = ContentHints::text("application/json");
        assert!(h.known_text());
        assert!(!h.known_binary());
        assert_eq!(h.media_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn content_hints_binary() {
        let h = ContentHints::binary("image/png");
        assert!(h.known_binary());
        assert!(!h.known_text());
    }

    // -- ItemLocation --

    #[test]
    fn item_location_display() {
        let loc = ItemLocation::new("github.com/org/repo/file.txt");
        assert_eq!(format!("{}", loc), "github.com/org/repo/file.txt");
    }

    #[test]
    fn item_location_with_url() {
        let loc = ItemLocation::with_url(
            "github.com/org/repo/file.txt",
            "https://github.com/org/repo/blob/main/file.txt",
        );
        assert!(loc.url.is_some());
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn item_location_empty_panics() {
        ItemLocation::new("");
    }

    // -- ScanItem + Builder --

    #[test]
    fn scan_item_builder_identity_consistency() {
        let item = test_scan_item(b"path/to/file.txt");
        assert!(item.check_identity_consistency());
    }

    #[test]
    fn scan_item_builder_with_hints_and_size() {
        let item = ScanItemBuilder::new(
            test_item_key(b"path.json"),
            test_item_ref(),
            test_version(),
            test_location(),
        )
        .size_hint(4096)
        .content_hints(ContentHints::text("application/json"))
        .build();

        assert_eq!(item.size_hint, Some(4096));
        assert!(item.content_hints.known_text());
    }

    // -- EnumerationBudget --

    #[test]
    fn enumeration_budget_construction() {
        let b = EnumerationBudget::new(100, 5000, 10);
        assert_eq!(b.max_items, 100);
        assert_eq!(b.max_wall_time_ms, 5000);
        assert_eq!(b.max_api_calls, 10);
    }

    #[test]
    #[should_panic(expected = "max_items must be > 0")]
    fn enumeration_budget_zero_items_panics() {
        EnumerationBudget::new(0, 5000, 10);
    }

    #[test]
    #[should_panic(expected = "max_wall_time_ms must be > 0")]
    fn enumeration_budget_zero_time_panics() {
        EnumerationBudget::new(100, 0, 10);
    }

    #[test]
    #[should_panic(expected = "max_api_calls must be > 0")]
    fn enumeration_budget_zero_api_panics() {
        EnumerationBudget::new(100, 5000, 0);
    }

    // -- ReadBudget --

    #[test]
    fn read_budget_construction() {
        let b = ReadBudget::new(1024 * 1024, 10_000);
        assert_eq!(b.max_bytes, 1024 * 1024);
        assert_eq!(b.max_wall_time_ms, 10_000);
    }

    #[test]
    #[should_panic(expected = "max_bytes must be > 0")]
    fn read_budget_zero_bytes_panics() {
        ReadBudget::new(0, 10_000);
    }

    // -- EnumerationPage --

    #[test]
    fn enumeration_page_ordering_empty() {
        let page = EnumerationPage {
            items: vec![],
            next_cursor: None,
            api_calls_used: 0,
        };
        assert!(page.check_ordering());
        assert!(page.is_last_page());
    }

    #[test]
    fn enumeration_page_ordering_sorted() {
        let page = EnumerationPage {
            items: vec![
                test_scan_item(b"aaa"),
                test_scan_item(b"bbb"),
                test_scan_item(b"ccc"),
            ],
            next_cursor: None,
            api_calls_used: 1,
        };
        assert!(page.check_ordering());
    }

    #[test]
    fn enumeration_page_ordering_unsorted() {
        let page = EnumerationPage {
            items: vec![
                test_scan_item(b"ccc"),
                test_scan_item(b"aaa"),
            ],
            next_cursor: None,
            api_calls_used: 1,
        };
        assert!(!page.check_ordering());
    }

    #[test]
    fn enumeration_page_not_last_when_cursor_present() {
        let page = EnumerationPage {
            items: vec![test_scan_item(b"aaa")],
            next_cursor: Some(Cursor::initial()),
            api_calls_used: 1,
        };
        assert!(!page.is_last_page());
    }

    // -- Property test stubs --

    // TODO: proptest for identity consistency:
    //   âˆ€ item_key: ScanItemBuilder::new(key, ...).build().check_identity_consistency()
    //
    // TODO: proptest for VersionId canonical bytes collision freedom:
    //   âˆ€ v1 != v2: canonical_hash(v1) != canonical_hash(v2)
    //
    // TODO: proptest for page ordering preservation:
    //   âˆ€ sorted items: EnumerationPage { items }.check_ordering() == true
    //
    // TODO: proptest for budget non-zero invariant:
    //   âˆ€ (a, b, c) where any == 0: EnumerationBudget::new(a, b, c) panics
}
