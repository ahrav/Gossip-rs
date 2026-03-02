//! # Scheduler Contract
//!
//! Run-scoped identifiers, engine contract, and scheduler limits.
//!
//! This module defines the foundational types that establish the scheduler's
//! correctness guarantees. These types are intentionally simple and `Copy` to
//! allow cheap passing through the system without allocation overhead.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         RunConfig                               │
//! │  ┌─────────────┐  ┌─────────────────────────────────────────┐  │
//! │  │   seed      │  │              Limits                     │  │
//! │  │ (u64)       │  │  ┌─────────────┬─────────────────────┐  │  │
//! │  │             │  │  │ in_flight_  │ buffered_bytes      │  │  │
//! │  │ Determinism │  │  │ objects/    │ queued_tasks        │  │  │
//! │  │ guarantee   │  │  │ reads       │                     │  │  │
//! │  └─────────────┘  │  └─────────────┴─────────────────────┘  │  │
//! │                   │         Backpressure tokens              │  │
//! │                   └─────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//!
//! ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
//! │  SourceId    │───▶│  ObjectId    │───▶│   ViewId     │
//! │  (run scope) │    │  (per-source)│    │  (per-object)│
//! └──────────────┘    └──────────────┘    └──────────────┘
//!       │                    │                   │
//!       └────────────────────┴───────────────────┘
//!                 Tracing without PII
//! ```
//!
//! ## Non-negotiable invariants
//!
//! ### Work-conserving
//! - Backpressure delays work, never drops it.
//! - When limits prevent progress, the scheduler blocks or parks and resumes later.
//!
//! ### Exactly-once (within a run)
//! - Each object version is scanned exactly once within a run, unless explicitly
//!   configured otherwise.
//! - Retries are bounded and observable (attempt count, reason, backoff).
//!
//! ### Hard caps (tokens)
//! - in-flight objects
//! - in-flight reads
//! - buffered bytes (buffer pool / byte budget)
//! - queued tasks
//!
//! ### Budget invariance
//! - Per-object and per-chunk budgets must be enforced identically regardless
//!   of concurrency and completion order.
//!
//! ### Cancellation is leak-free
//! - Cancel is explicit and leak-free.
//! - Buffers and tokens are always returned exactly once, even on early exit paths.

/// Run-scoped source identifier.
///
/// Represents a single data source (e.g., a Git repository, S3 bucket, or filesystem path)
/// within a scan run. Sources are discovered and assigned IDs at the start of a run.
///
/// # Privacy
///
/// **Do not log raw paths/URLs/etc.** Use this ID for tracing and metrics instead.
/// This prevents accidental PII exposure in logs while maintaining debuggability.
///
/// # Ordering
///
/// IDs are monotonically increasing within a run if and only if discovery order is
/// deterministic (controlled by [`RunConfig::seed`]). Do not rely on ID ordering
/// for correctness—only for reproducibility in testing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceId(pub u32);

/// Run-scoped object identifier.
///
/// Uniquely identifies a scannable object (file, blob, archive entry) within a run.
/// Objects belong to exactly one source; the `(source, idx)` pair is unique per run.
///
/// # Privacy
///
/// **Do not log raw paths/URLs.** Use `ObjectId` for tracing and finding attribution.
/// The scheduler maintains an internal mapping from `ObjectId` → metadata when needed.
///
/// # Structure
///
/// ```text
/// ObjectId { source: SourceId(0), idx: 42 }
///            └─── which source ───┘  └─ object index within source
/// ```
///
/// The `idx` field is assigned during object enumeration and is monotonic within
/// a source if enumeration order is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId {
    /// The source this object belongs to.
    pub source: SourceId,
    /// Object index within the source (0-based, monotonic if deterministic).
    pub idx: u32,
}

/// View identity for bytes passed to the detection engine.
///
/// When scanning an object, the scheduler may produce multiple "views" of the same bytes:
/// - View 0: Raw bytes as read from storage
/// - View 1: URL-decoded bytes
/// - View 2: Base64-decoded bytes
/// - etc.
///
/// The engine scans each view independently; findings include the `ViewId` so consumers
/// can trace back to which transformation revealed the secret.
///
/// # Design rationale
///
/// The scheduler is agnostic to view semantics—it simply passes this ID through.
/// This keeps the scheduler decoupled from transform logic while preserving
/// attribution in findings. The transform layer is responsible for assigning
/// meaningful view IDs.
///
/// # Default
///
/// `ViewId(0)` conventionally represents raw/untransformed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ViewId(pub u16);

/// What the detection engine declares about chunking correctness.
///
/// The scheduler chunks large objects to bound memory usage. To avoid missing secrets
/// that span chunk boundaries, the scheduler needs to know the engine's requirements:
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────────┐
/// │                          Object bytes                               │
/// └─────────────────────────────────────────────────────────────────────┘
///
/// Chunked with overlap:
/// ┌────────────────────────┐
/// │       Chunk 0          │
/// └────────────────────────┘
///                 ┌────────────────────────┐
///                 │   overlap   │ Chunk 1  │
///                 └────────────────────────┘
///                                  ┌────────────────────────┐
///                                  │ overlap │   Chunk 2    │
///                                  └────────────────────────┘
/// ```
///
/// # Contract semantics
///
/// - **Bounded (`Some(n)`)**: The engine's regex patterns have a maximum match span
///   of `n` bytes. Providing `n` bytes of overlap between chunks guarantees no
///   boundary-spanning secret is missed. This is the common case for fixed-pattern
///   engines.
///
/// - **Unbounded (`None`)**: The engine has patterns with unbounded match spans
///   (e.g., multi-line secrets, streaming decoders with internal state). The scheduler
///   must use streaming-state scanning instead of simple overlap.
///
/// # Design rationale
///
/// This is intentionally phrased as "required overlap" to match the engine's
/// `required_overlap()` semantics, not as an interpretation of max span. The
/// scheduler trusts the engine's declaration and does not validate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineContract {
    /// Required overlap in bytes for overlap-only chunking correctness.
    ///
    /// - `Some(n)`: Overlap-only scanning is safe if each chunk includes at least
    ///   `n` bytes from the previous chunk as a prefix.
    /// - `None`: Overlap-only scanning is **not** safe; streaming-state scanning required.
    pub required_overlap_bytes: Option<u32>,
}

impl EngineContract {
    /// Create a contract for an engine with bounded overlap requirement.
    ///
    /// Use this when the engine's maximum pattern span is known and finite.
    ///
    /// # Example
    ///
    /// ```
    /// use scanner_rs::scheduler::contract::EngineContract;
    ///
    /// // Engine with max 256-byte patterns
    /// let contract = EngineContract::bounded(256);
    /// assert!(contract.overlap_only_safe());
    /// ```
    pub const fn bounded(overlap_bytes: u32) -> Self {
        Self {
            required_overlap_bytes: Some(overlap_bytes),
        }
    }

    /// Create a contract for an engine that requires streaming state.
    ///
    /// Use this when the engine has patterns with unbounded spans (e.g., multi-line
    /// secrets, streaming decoders). The scheduler will use streaming-state scanning
    /// instead of overlap-based chunking.
    ///
    /// # Example
    ///
    /// ```
    /// use scanner_rs::scheduler::contract::EngineContract;
    ///
    /// // Engine with unbounded patterns (e.g., streaming base64 decoder)
    /// let contract = EngineContract::unbounded();
    /// assert!(!contract.overlap_only_safe());
    /// ```
    pub const fn unbounded() -> Self {
        Self {
            required_overlap_bytes: None,
        }
    }

    /// Check if overlap-only chunking is safe with this contract.
    ///
    /// Returns `true` if the engine has a bounded overlap requirement, meaning
    /// simple overlap-based chunking will not miss boundary-spanning secrets.
    pub const fn overlap_only_safe(&self) -> bool {
        self.required_overlap_bytes.is_some()
    }
}

/// Scheduler limits for backpressure control.
///
/// These limits are enforced as **hard caps** via token-based semaphores. When a limit
/// is reached, the scheduler blocks (work-conserving) rather than dropping work.
///
/// # Invariants
///
/// - All limits must be non-zero. Zero limits would mean no work can proceed.
/// - Limits are validated at scheduler initialization via [`Limits::validate`].
///
/// # Tuning guidance
///
/// | Limit | Increase if... | Decrease if... |
/// |-------|----------------|----------------|
/// | `in_flight_objects` | CPU-bound, low memory pressure | Memory-bound, many large objects |
/// | `in_flight_reads` | High-latency storage (S3, network) | Local SSD, hitting IOPS limits |
/// | `buffered_bytes` | Large objects, plenty of RAM | Memory-constrained environment |
/// | `queued_tasks` | Bursty discovery, many small objects | Steady-state throughput |
///
/// # Default values
///
/// Defaults are tuned for a server with ~32 cores and ~64 GiB RAM scanning mixed
/// repositories. Adjust based on your workload characteristics.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Max objects in flight (discovered but not fully scanned).
    ///
    /// An object is "in flight" from the moment it's dequeued for processing until
    /// all its chunks have been scanned and findings emitted. Higher values improve
    /// throughput but increase memory pressure.
    pub in_flight_objects: u32,

    /// Max concurrent read/fetch operations.
    ///
    /// Controls parallelism of I/O operations (disk reads, S3 fetches, etc.).
    /// Set based on storage characteristics: higher for high-latency remote storage,
    /// lower for local SSDs where IOPS is the bottleneck.
    pub in_flight_reads: u32,

    /// Max bytes buffered across all in-flight chunks.
    ///
    /// This is the primary memory-bounding mechanism. The scheduler will not start
    /// reading new objects if doing so would exceed this limit. Includes both
    /// raw buffers and any transformation buffers (decode, decompress).
    pub buffered_bytes: u64,

    /// Max tasks queued across injector and local queues.
    ///
    /// Bounds the scheduler's internal task queue depth. Tasks include chunk-scan
    /// operations, transform applications, and finding emissions. Higher values
    /// smooth out discovery bursts but increase latency variance.
    pub queued_tasks: u32,
}

impl Limits {
    /// Validate that all limits are non-zero.
    ///
    /// Called automatically by [`RunConfig::validate`]. Zero limits would deadlock
    /// the scheduler since no work could ever proceed.
    ///
    /// # Panics
    ///
    /// Panics with a descriptive message if any limit is zero.
    pub fn validate(&self) {
        assert!(self.in_flight_objects > 0, "in_flight_objects must be > 0");
        assert!(self.in_flight_reads > 0, "in_flight_reads must be > 0");
        assert!(self.buffered_bytes > 0, "buffered_bytes must be > 0");
        assert!(self.queued_tasks > 0, "queued_tasks must be > 0");
    }
}

impl Default for Limits {
    /// Default limits tuned for ~32 cores, ~64 GiB RAM.
    ///
    /// - `in_flight_objects`: 1024 (handles mixed repo sizes)
    /// - `in_flight_reads`: 256 (good for SSDs and moderate network latency)
    /// - `buffered_bytes`: 512 MiB (conservative memory footprint)
    /// - `queued_tasks`: 65536 (handles discovery bursts)
    fn default() -> Self {
        Self {
            in_flight_objects: 1024,
            in_flight_reads: 256,
            buffered_bytes: 512 * 1024 * 1024, // 512 MiB
            queued_tasks: 65536,
        }
    }
}

/// Run configuration for deterministic, reproducible scans.
///
/// This struct captures the configuration that must be fixed at the start of a scan
/// run to ensure reproducibility. The same `RunConfig` on the same inputs produces
/// identical scheduling decisions and, consequently, identical findings order.
///
/// # Reproducibility guarantee
///
/// Given:
/// - Same `seed`
/// - Same input sources in same order
/// - Same engine configuration
///
/// The scheduler guarantees:
/// - Same object processing order
/// - Same chunk boundaries
/// - Same finding emission order
///
/// This is critical for differential testing, regression hunting, and audit trails.
///
/// # Future extensions
///
/// Scheduler policy (priority functions, fairness weights) will grow later, but
/// `seed` and `limits` belong here from day 0 as they affect determinism.
#[derive(Clone, Copy, Debug, Default)]
pub struct RunConfig {
    /// Seed for deterministic scheduling decisions.
    ///
    /// Controls all randomized behavior (shuffling, work-stealing victim selection, etc.).
    /// A seed of 0 is explicitly allowed—the RNG module maps it to a non-zero internal
    /// state to avoid degenerate PRNG behavior.
    ///
    /// Use a fixed seed for reproducible runs; use a random seed (e.g., from system
    /// entropy) for production scans to avoid pathological input ordering.
    pub seed: u64,

    /// Resource limits for backpressure control.
    ///
    /// See [`Limits`] for per-field documentation and tuning guidance.
    pub limits: Limits,
}

impl RunConfig {
    /// Create a new run config with the given seed and default limits.
    ///
    /// # Example
    ///
    /// ```
    /// use scanner_rs::scheduler::contract::RunConfig;
    ///
    /// // Reproducible run with fixed seed
    /// let config = RunConfig::new(42);
    /// config.validate();
    /// ```
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            limits: Limits {
                in_flight_objects: 1024,
                in_flight_reads: 256,
                buffered_bytes: 512 * 1024 * 1024,
                queued_tasks: 65536,
            },
        }
    }

    /// Validate the configuration before starting a run.
    ///
    /// Should be called at scheduler initialization. Validation is explicit rather
    /// than automatic in constructors to allow building configs incrementally.
    ///
    /// # Panics
    ///
    /// Panics if any limit is zero (see [`Limits::validate`]).
    pub fn validate(&self) {
        self.limits.validate();
        // seed=0 is explicitly allowed; rng module handles it.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_id_equality() {
        assert_eq!(SourceId(0), SourceId(0));
        assert_ne!(SourceId(0), SourceId(1));
    }

    #[test]
    fn object_id_equality() {
        let a = ObjectId {
            source: SourceId(0),
            idx: 42,
        };
        let b = ObjectId {
            source: SourceId(0),
            idx: 42,
        };
        let c = ObjectId {
            source: SourceId(1),
            idx: 42,
        };

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn engine_contract_bounded() {
        let contract = EngineContract::bounded(256);
        assert!(contract.overlap_only_safe());
        assert_eq!(contract.required_overlap_bytes, Some(256));
    }

    #[test]
    fn engine_contract_unbounded() {
        let contract = EngineContract::unbounded();
        assert!(!contract.overlap_only_safe());
        assert_eq!(contract.required_overlap_bytes, None);
    }

    #[test]
    fn limits_default_valid() {
        let limits = Limits::default();
        limits.validate(); // Should not panic
    }

    #[test]
    #[should_panic(expected = "in_flight_objects must be > 0")]
    fn limits_zero_objects_panics() {
        let limits = Limits {
            in_flight_objects: 0,
            ..Default::default()
        };
        limits.validate();
    }

    #[test]
    fn run_config_default_valid() {
        let config = RunConfig::default();
        config.validate(); // Should not panic
    }
}
