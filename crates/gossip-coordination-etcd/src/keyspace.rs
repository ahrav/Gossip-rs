//! Deterministic etcd path construction for coordination records.
//!
//! Every coordination record (run, shard, ownership, active-index) maps to
//! exactly one etcd key. This module owns the mapping from identity tuples
//! (`TenantId`, `RunId`, `ShardId`) to ASCII key paths, so persistence code
//! never builds raw strings itself.
//!
//! # Key layout
//!
//! All paths are rooted at a caller-chosen namespace prefix (e.g. `/gossip/v1`).
//! The tree is designed for etcd prefix scans — each category of record sits
//! under a distinct path segment so a single `get_prefix` call can enumerate
//! all records of that kind without false positives.
//!
//! ```text
//! {prefix}/
//!   tenants/
//!     {tenant_hex}/                        # 64 lowercase hex chars (32-byte TenantId)
//!       runs/
//!         {run_hex}/                       # 16 zero-padded hex chars (u64 RunId)
//!           shards/
//!             {shard_hex}                  # 16 zero-padded hex chars (u64 ShardId)
//!             {shard_hex}/owner            # per-shard ownership key
//!           shards_active/
//!             {shard_hex}                  # active-shard index entry
//!       runs_active/
//!         {run_hex}                        # active-run index entry
//! ```
//!
//! # Design rationale
//!
//! - **`runs/` vs `runs_active/`**: Record keys and active-index keys are
//!   siblings under the tenant, not nested. This avoids a prefix scan on
//!   `runs/` from pulling in active-index entries, and vice versa.
//! - **`shards/` vs `shards_active/`**: Same sibling separation under each
//!   run key. See [`EtcdKeyspace::shard_records_scan_prefix`] for the
//!   trailing-slash convention that prevents cross-category matches.
//! - **Fixed-width hex encoding**: `RunId` and `ShardId` are zero-padded to
//!   16 hex characters, `TenantId` to 64 hex characters. Fixed width means
//!   lexicographic key order matches numeric order, which keeps etcd range
//!   scans predictable.
//! - **Lowercase-only hex**: All hex output uses `[0-9a-f]`. No uppercase
//!   letters appear, so byte-level equality works for key comparison.
//!
//! # Buffer-reuse API
//!
//! Every key method has a corresponding `_into` variant that appends into a
//! caller-owned `&mut String` without clearing it first. This allows hot-path
//! callers to reuse a single buffer across multiple key constructions,
//! avoiding per-call heap allocation. The convenience methods (returning
//! `String`) delegate to their `_into` counterparts internally.

use std::fmt;
use std::fmt::Write;

use gossip_contracts::identity::{RunId, ShardId, TenantId};

/// Validation errors for [`EtcdKeyspace`] construction.
///
/// The prefix rules exist to guarantee that every generated key is an
/// absolute etcd path and that no key contains accidental double slashes
/// (which would create invisible empty path segments in the etcd keyspace).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdKeyspaceError {
    /// Prefix is empty after surrounding whitespace is trimmed.
    EmptyPrefix,
    /// Prefix must start with `/` to form absolute etcd paths.
    PrefixMustStartWithSlash,
    /// Prefix must not end with `/` (unless it is exactly `"/"`), because
    /// path joins would produce double slashes.
    PrefixMustNotEndWithSlash,
    /// Prefix contains consecutive slashes (`//`), which would create
    /// invisible empty path segments in the etcd keyspace.
    PrefixContainsDoubleSlash,
}

impl fmt::Display for EtcdKeyspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPrefix => f.write_str("etcd keyspace prefix must not be empty"),
            Self::PrefixMustStartWithSlash => {
                f.write_str("etcd keyspace prefix must start with '/'")
            }
            Self::PrefixMustNotEndWithSlash => {
                f.write_str("etcd keyspace prefix must not end with '/' unless it is exactly '/'")
            }
            Self::PrefixContainsDoubleSlash => {
                f.write_str("etcd keyspace prefix must not contain consecutive slashes '//'")
            }
        }
    }
}

impl std::error::Error for EtcdKeyspaceError {}

/// Deterministic builder for the etcd coordination key layout.
///
/// Constructed once from a validated namespace prefix (e.g. `/gossip/v1`)
/// and reused for the lifetime of the backend. All generated keys are
/// pure-ASCII, deterministic, and suitable for both exact `get` lookups
/// and etcd prefix-range scans.
///
/// # Invariants
///
/// - The stored prefix always starts with `/` and never ends with `/`
///   (unless it is exactly `"/"`).
/// - Every public method returns a fully-formed absolute etcd key
///   containing no double-slash sequences.
///
/// # Examples
///
/// ```
/// # use gossip_coordination_etcd::EtcdKeyspace;
/// # use gossip_contracts::identity::{RunId, ShardId, TenantId};
/// let ks = EtcdKeyspace::new("/gossip/v1").unwrap();
/// let t = TenantId::from_bytes([0xAB; 32]);
/// let r = RunId::from_raw(0x42);
///
/// // Exact key for a run record:
/// assert!(ks.run_record_key(t, r).starts_with("/gossip/v1/tenants/"));
///
/// // Scan prefix for all shard records under that run:
/// assert!(ks.shard_records_scan_prefix(t, r).ends_with("/shards/"));
///
/// // Buffer-reuse variant appends without clearing:
/// let mut buf = String::new();
/// ks.run_record_key_into(&mut buf, t, r);
/// assert!(buf.starts_with("/gossip/v1/tenants/"));
/// buf.clear();
/// ks.shard_records_scan_prefix_into(&mut buf, t, r);
/// assert!(buf.ends_with("/shards/"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtcdKeyspace {
    prefix: String,
}

impl EtcdKeyspace {
    /// Create a validated keyspace rooted at `prefix`.
    ///
    /// Leading and trailing whitespace is stripped before validation, so
    /// values read from environment variables or config files with
    /// incidental whitespace normalize cleanly.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdKeyspaceError`] if the trimmed prefix is empty,
    /// does not start with `/`, or ends with `/` (unless it is `"/"`).
    pub fn new(prefix: impl Into<String>) -> Result<Self, EtcdKeyspaceError> {
        let prefix = prefix.into().trim().to_owned();
        if prefix.is_empty() {
            return Err(EtcdKeyspaceError::EmptyPrefix);
        }
        if !prefix.starts_with('/') {
            return Err(EtcdKeyspaceError::PrefixMustStartWithSlash);
        }
        if prefix.ends_with('/') && prefix.len() > 1 {
            return Err(EtcdKeyspaceError::PrefixMustNotEndWithSlash);
        }
        if prefix.contains("//") {
            return Err(EtcdKeyspaceError::PrefixContainsDoubleSlash);
        }
        Ok(Self { prefix })
    }

    /// Returns the validated root namespace prefix as stored.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    // -----------------------------------------------------------------------
    // Tenant-scoped prefixes
    // -----------------------------------------------------------------------

    /// Scan prefix for all tenant subtrees: `{prefix}/tenants`.
    ///
    /// Appends the key into `buf` without clearing it first, enabling
    /// buffer reuse across multiple key constructions.
    pub fn tenants_prefix_into(&self, buf: &mut String) {
        self.join_namespace_into(buf, "tenants");
    }

    /// Scan prefix for all tenant subtrees: `{prefix}/tenants`.
    #[must_use]
    pub fn tenants_prefix(&self) -> String {
        let mut buf = String::new();
        self.tenants_prefix_into(&mut buf);
        buf
    }

    /// Root of a single tenant's subtree:
    /// `{prefix}/tenants/{tenant_hex}`.
    ///
    /// `tenant_hex` is the 64-character lowercase hex encoding of the
    /// 32-byte [`TenantId`]. Appends into `buf` without clearing.
    pub fn tenant_prefix_into(&self, buf: &mut String, tenant: TenantId) {
        self.tenants_prefix_into(buf);
        buf.push('/');
        tenant_hex_into(buf, tenant);
    }

    /// Root of a single tenant's subtree: `{prefix}/tenants/{tenant_hex}`.
    ///
    /// `tenant_hex` is the 64-character lowercase hex encoding of the
    /// 32-byte [`TenantId`].
    #[must_use]
    pub fn tenant_prefix(&self, tenant: TenantId) -> String {
        let mut buf = String::new();
        self.tenant_prefix_into(&mut buf, tenant);
        buf
    }

    // -----------------------------------------------------------------------
    // Run record keys
    // -----------------------------------------------------------------------

    /// Common segment for run records under a tenant:
    /// `{prefix}/tenants/{tenant_hex}/runs`.
    ///
    /// This is the *non-trailing-slash* form used for building child keys.
    /// Use [`run_records_scan_prefix_into`](Self::run_records_scan_prefix_into)
    /// for etcd prefix scans to avoid matching sibling `runs_active/` keys.
    /// Appends into `buf` without clearing.
    pub fn runs_prefix_into(&self, buf: &mut String, tenant: TenantId) {
        self.tenant_prefix_into(buf, tenant);
        buf.push_str("/runs");
    }

    /// Common segment for run records under a tenant:
    /// `{prefix}/tenants/{tenant_hex}/runs`.
    ///
    /// This is the *non-trailing-slash* form used for building child keys.
    /// Use [`run_records_scan_prefix`](Self::run_records_scan_prefix) for
    /// etcd prefix scans to avoid matching sibling `runs_active/` keys.
    #[must_use]
    pub fn runs_prefix(&self, tenant: TenantId) -> String {
        let mut buf = String::new();
        self.runs_prefix_into(&mut buf, tenant);
        buf
    }

    /// Scan prefix for enumerating run records under a tenant:
    /// `{prefix}/tenants/{tenant_hex}/runs/`.
    ///
    /// The trailing slash is critical. Without it, an etcd prefix scan on
    /// `.../runs` would also match `.../runs_active/...` keys because
    /// `"runs"` is a prefix of `"runs_active"`. The trailing slash
    /// restricts the scan to children of the `runs/` directory only.
    /// Appends into `buf` without clearing.
    pub fn run_records_scan_prefix_into(&self, buf: &mut String, tenant: TenantId) {
        self.runs_prefix_into(buf, tenant);
        buf.push('/');
    }

    /// Scan prefix for enumerating run records under a tenant:
    /// `{prefix}/tenants/{tenant_hex}/runs/`.
    ///
    /// The trailing slash is critical. Without it, an etcd prefix scan on
    /// `.../runs` would also match `.../runs_active/...` keys because
    /// `"runs"` is a prefix of `"runs_active"`. The trailing slash
    /// restricts the scan to children of the `runs/` directory only.
    #[must_use]
    pub fn run_records_scan_prefix(&self, tenant: TenantId) -> String {
        let mut buf = String::new();
        self.run_records_scan_prefix_into(&mut buf, tenant);
        buf
    }

    /// Exact key for a run record:
    /// `{prefix}/tenants/{tenant_hex}/runs/{run_hex}`.
    ///
    /// `run_hex` is the 16-character zero-padded lowercase hex encoding of
    /// the `u64` [`RunId`]. Appends into `buf` without clearing.
    pub fn run_record_key_into(&self, buf: &mut String, tenant: TenantId, run: RunId) {
        self.runs_prefix_into(buf, tenant);
        buf.push('/');
        run_hex_into(buf, run);
    }

    /// Exact key for a run record:
    /// `{prefix}/tenants/{tenant_hex}/runs/{run_hex}`.
    ///
    /// `run_hex` is the 16-character zero-padded lowercase hex encoding of
    /// the `u64` [`RunId`].
    #[must_use]
    pub fn run_record_key(&self, tenant: TenantId, run: RunId) -> String {
        let mut buf = String::new();
        self.run_record_key_into(&mut buf, tenant, run);
        buf
    }

    // -----------------------------------------------------------------------
    // Shard record keys
    // -----------------------------------------------------------------------

    /// Common segment for shard records under a run:
    /// `{run_record_key}/shards`.
    ///
    /// This is the *non-trailing-slash* form. Use
    /// [`shard_records_scan_prefix_into`](Self::shard_records_scan_prefix_into)
    /// for prefix scans to avoid matching sibling `shards_active/` keys.
    /// Appends into `buf` without clearing.
    pub fn run_shards_prefix_into(&self, buf: &mut String, tenant: TenantId, run: RunId) {
        self.run_record_key_into(buf, tenant, run);
        buf.push_str("/shards");
    }

    /// Common segment for shard records under a run:
    /// `{run_record_key}/shards`.
    ///
    /// This is the *non-trailing-slash* form. Use
    /// [`shard_records_scan_prefix`](Self::shard_records_scan_prefix) for
    /// prefix scans to avoid matching sibling `shards_active/` keys.
    #[must_use]
    pub fn run_shards_prefix(&self, tenant: TenantId, run: RunId) -> String {
        let mut buf = String::new();
        self.run_shards_prefix_into(&mut buf, tenant, run);
        buf
    }

    /// Scan prefix for enumerating shard records under a run:
    /// `{run_record_key}/shards/`.
    ///
    /// The trailing slash is critical. Without it, an etcd prefix scan on
    /// `.../shards` would also match `.../shards_active/...` keys because
    /// `"shards"` is a prefix of `"shards_active"`. The trailing slash
    /// restricts the scan to children of the `shards/` directory only.
    /// Appends into `buf` without clearing.
    pub fn shard_records_scan_prefix_into(&self, buf: &mut String, tenant: TenantId, run: RunId) {
        self.run_shards_prefix_into(buf, tenant, run);
        buf.push('/');
    }

    /// Scan prefix for enumerating shard records under a run:
    /// `{run_record_key}/shards/`.
    ///
    /// The trailing slash is critical. Without it, an etcd prefix scan on
    /// `.../shards` would also match `.../shards_active/...` keys because
    /// `"shards"` is a prefix of `"shards_active"`. The trailing slash
    /// restricts the scan to children of the `shards/` directory only.
    #[must_use]
    pub fn shard_records_scan_prefix(&self, tenant: TenantId, run: RunId) -> String {
        let mut buf = String::new();
        self.shard_records_scan_prefix_into(&mut buf, tenant, run);
        buf
    }

    /// Exact key for a shard record:
    /// `{run_record_key}/shards/{shard_hex}`.
    ///
    /// `shard_hex` is the 16-character zero-padded lowercase hex encoding
    /// of the `u64` [`ShardId`]. Appends into `buf` without clearing.
    pub fn shard_record_key_into(
        &self,
        buf: &mut String,
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
    ) {
        self.run_shards_prefix_into(buf, tenant, run);
        buf.push('/');
        shard_hex_into(buf, shard);
    }

    /// Exact key for a shard record:
    /// `{run_record_key}/shards/{shard_hex}`.
    ///
    /// `shard_hex` is the 16-character zero-padded lowercase hex encoding
    /// of the `u64` [`ShardId`].
    #[must_use]
    pub fn shard_record_key(&self, tenant: TenantId, run: RunId, shard: ShardId) -> String {
        let mut buf = String::new();
        self.shard_record_key_into(&mut buf, tenant, run, shard);
        buf
    }

    /// Exact key for shard ownership:
    /// `{run_record_key}/shards/{shard_hex}/owner`.
    ///
    /// Stored as a child of the shard record key so a delete on the shard
    /// record key prefix also removes the ownership key. Appends into `buf`
    /// without clearing.
    pub fn shard_owner_key_into(
        &self,
        buf: &mut String,
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
    ) {
        self.shard_record_key_into(buf, tenant, run, shard);
        buf.push_str("/owner");
    }

    /// Exact key for shard ownership:
    /// `{run_record_key}/shards/{shard_hex}/owner`.
    ///
    /// Stored as a child of the shard record key so a delete on the shard
    /// record key prefix also removes the ownership key.
    #[must_use]
    pub fn shard_owner_key(&self, tenant: TenantId, run: RunId, shard: ShardId) -> String {
        let mut buf = String::new();
        self.shard_owner_key_into(&mut buf, tenant, run, shard);
        buf
    }

    // -----------------------------------------------------------------------
    // Active-index keys
    // -----------------------------------------------------------------------
    //
    // Active indexes are lightweight marker keys that allow listing only
    // active runs/shards without scanning (and filtering) the full record
    // keyspace.

    /// Scan prefix for active-run index entries:
    /// `{prefix}/tenants/{tenant_hex}/runs_active`.
    ///
    /// Lives as a sibling of `runs/` under the tenant — not nested inside
    /// `runs/` — so that a prefix scan on `runs/` returns only run records.
    /// Appends into `buf` without clearing.
    pub fn runs_active_prefix_into(&self, buf: &mut String, tenant: TenantId) {
        self.tenant_prefix_into(buf, tenant);
        buf.push_str("/runs_active");
    }

    /// Scan prefix for active-run index entries:
    /// `{prefix}/tenants/{tenant_hex}/runs_active`.
    ///
    /// Lives as a sibling of `runs/` under the tenant — not nested inside
    /// `runs/` — so that a prefix scan on `runs/` returns only run records.
    #[must_use]
    pub fn runs_active_prefix(&self, tenant: TenantId) -> String {
        let mut buf = String::new();
        self.runs_active_prefix_into(&mut buf, tenant);
        buf
    }

    /// Exact key for an active-run index entry:
    /// `{prefix}/tenants/{tenant_hex}/runs_active/{run_hex}`.
    /// Appends into `buf` without clearing.
    pub fn run_active_index_key_into(&self, buf: &mut String, tenant: TenantId, run: RunId) {
        self.runs_active_prefix_into(buf, tenant);
        buf.push('/');
        run_hex_into(buf, run);
    }

    /// Exact key for an active-run index entry:
    /// `{prefix}/tenants/{tenant_hex}/runs_active/{run_hex}`.
    #[must_use]
    pub fn run_active_index_key(&self, tenant: TenantId, run: RunId) -> String {
        let mut buf = String::new();
        self.run_active_index_key_into(&mut buf, tenant, run);
        buf
    }

    /// Scan prefix for active-shard index entries under a run:
    /// `{run_record_key}/shards_active`.
    ///
    /// Lives as a sibling of `shards/` under the run key — not nested
    /// inside `shards/` — for the same scan-isolation reason as
    /// [`runs_active_prefix`](Self::runs_active_prefix). Appends into
    /// `buf` without clearing.
    pub fn shards_active_prefix_into(&self, buf: &mut String, tenant: TenantId, run: RunId) {
        self.run_record_key_into(buf, tenant, run);
        buf.push_str("/shards_active");
    }

    /// Scan prefix for active-shard index entries under a run:
    /// `{run_record_key}/shards_active`.
    ///
    /// Lives as a sibling of `shards/` under the run key — not nested
    /// inside `shards/` — for the same scan-isolation reason as
    /// [`runs_active_prefix`](Self::runs_active_prefix).
    #[must_use]
    pub fn shards_active_prefix(&self, tenant: TenantId, run: RunId) -> String {
        let mut buf = String::new();
        self.shards_active_prefix_into(&mut buf, tenant, run);
        buf
    }

    /// Exact key for an active-shard index entry:
    /// `{run_record_key}/shards_active/{shard_hex}`.
    /// Appends into `buf` without clearing.
    pub fn shard_active_index_key_into(
        &self,
        buf: &mut String,
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
    ) {
        self.shards_active_prefix_into(buf, tenant, run);
        buf.push('/');
        shard_hex_into(buf, shard);
    }

    /// Exact key for an active-shard index entry:
    /// `{run_record_key}/shards_active/{shard_hex}`.
    #[must_use]
    pub fn shard_active_index_key(&self, tenant: TenantId, run: RunId, shard: ShardId) -> String {
        let mut buf = String::new();
        self.shard_active_index_key_into(&mut buf, tenant, run, shard);
        buf
    }

    /// Appends `suffix` to the prefix with a `/` separator.
    ///
    /// Handles the root prefix (`"/"`) as a special case: joining `"/"`
    /// with `"tenants"` produces `"/tenants"`, not `"//tenants"`.
    fn join_namespace_into(&self, buf: &mut String, suffix: &str) {
        debug_assert!(!suffix.starts_with('/'));
        if self.prefix == "/" {
            buf.push('/');
        } else {
            buf.push_str(&self.prefix);
            buf.push('/');
        }
        buf.push_str(suffix);
    }
}

// ---------------------------------------------------------------------------
// Hex encoding helpers
// ---------------------------------------------------------------------------
//
// All identity types are encoded as fixed-width lowercase hex so that etcd
// keys are human-readable in `etcdctl` output and lexicographic key order
// matches numeric order (important for range scans).

/// Append a 32-byte `TenantId` as 64 lowercase hex characters into `buf`.
fn tenant_hex_into(buf: &mut String, tenant: TenantId) {
    encode_hex_into(buf, tenant.as_bytes());
}

/// Append a `u64` `RunId` as 16 zero-padded lowercase hex characters into `buf`.
fn run_hex_into(buf: &mut String, run: RunId) {
    write!(buf, "{:016x}", run.as_raw()).expect("write to String is infallible");
}

/// Append a `u64` `ShardId` as 16 zero-padded lowercase hex characters into `buf`.
fn shard_hex_into(buf: &mut String, shard: ShardId) {
    write!(buf, "{:016x}", shard.as_raw()).expect("write to String is infallible");
}

/// Append a byte-slice as lowercase hex into `buf` using a lookup table.
///
/// Produces exactly `bytes.len() * 2` ASCII characters. Uses a 16-entry
/// LUT instead of `format!` to avoid per-byte format-string parsing.
fn encode_hex_into(buf: &mut String, bytes: &[u8]) {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    buf.reserve(bytes.len() * 2);
    for &byte in bytes {
        buf.push(LUT[(byte >> 4) as usize] as char);
        buf.push(LUT[(byte & 0x0f) as usize] as char);
    }
}
