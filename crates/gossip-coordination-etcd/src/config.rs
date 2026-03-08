//! Validated configuration for the etcd coordination backend.
//!
//! [`EtcdCoordinatorConfig`] carries connection parameters (endpoints,
//! namespace prefix) and persistence-tuning knobs (owner lease TTL,
//! optimistic CAS retry budget). All construction paths normalize
//! whitespace and validate invariants eagerly, so invalid configs are
//! rejected before any etcd connection attempt.
//!
//! # Defaults
//!
//! | Parameter | Default | Rationale |
//! |-----------|---------|-----------|
//! | Connect timeout | 5 s | Fast failure for unreachable endpoints |
//! | Owner lease TTL | 60 s | Wall-clock etcd lease for shard owner keys |
//! | Optimistic txn retries | 8 | Bounds CAS retry loops on fenced mutations |
//! | Max children per split op | 8 | Keeps split transactions comfortably below common etcd txn-op caps |

use std::fmt;
use std::time::Duration;

use gossip_contracts::coordination::limits::MAX_SPLIT_CHILDREN;

/// TCP connect timeout for the initial etcd client connection.
pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default wall-clock TTL (in seconds) for etcd leases attached to shard
/// owner keys. If a worker dies without releasing its lease, the owner key
/// is automatically deleted after this duration.
pub(crate) const DEFAULT_OWNER_LEASE_TTL_SECS: i64 = 60;

/// Default number of optimistic read-modify-write retry loops around
/// a fenced etcd transaction before giving up and returning an error.
pub(crate) const DEFAULT_OPTIMISTIC_TXN_RETRIES: usize = 8;

/// Default cap on the number of children published in a single split
/// transaction.
pub(crate) const DEFAULT_MAX_CHILDREN_PER_OP: usize = 8;

/// Validated configuration for the etcd coordination backend.
///
/// A complete config carries both connection settings and persistence-tuning
/// knobs:
///
/// - **Endpoints** identify the etcd members to contact.
/// - **Namespace prefix** scopes all coordination keys under a single etcd
///   subtree.
/// - **Owner lease TTL** controls the wall-clock etcd lease attached to shard
///   owner keys.
/// - **Optimistic txn retries** bounds compare-and-retry loops around fenced
///   mutations.
/// - **Max children per split op** bounds the fanout of one atomic
///   `split_replace` publication. Raising it also raises the transaction
///   write count (`3 + 2 * children`), so operators must keep it within
///   their cluster's txn-op budget.
#[derive(Clone)]
pub struct EtcdCoordinatorConfig {
    endpoints: Vec<String>,
    namespace_prefix: String,
    owner_lease_ttl_secs: i64,
    optimistic_txn_retries: usize,
    max_children_per_op: usize,
    /// Optional username/password pair for etcd authentication.
    auth: Option<(String, String)>,
    /// Optional TLS configuration for encrypted etcd connections.
    #[cfg(feature = "tls")]
    tls: Option<etcd_client::TlsOptions>,
}

/// Custom `Debug` implementation that redacts sensitive fields.
///
/// - Endpoint URIs with embedded `user:password@host` credentials are
///   replaced with `***@host` to prevent credential leakage in logs.
/// - The `auth` password field is printed as `[REDACTED]`.
/// - TLS configuration is shown as `[configured]` when present.
impl fmt::Debug for EtcdCoordinatorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Replace `user:password@host` with `***@host`, preserving the
        // scheme prefix and hostname for diagnostic usefulness.
        fn redact_endpoint(endpoint: &str) -> String {
            if let Some(scheme_end) = endpoint.find("://") {
                let authority_start = scheme_end + 3;
                let rest = &endpoint[authority_start..];
                let path_start = rest.find('/').unwrap_or(rest.len());
                if let Some(at_pos) = rest[..path_start].find('@') {
                    return format!("{}://***@{}", &endpoint[..scheme_end], &rest[at_pos + 1..]);
                }
            }
            endpoint.to_owned()
        }

        let redacted: Vec<String> = self.endpoints.iter().map(|e| redact_endpoint(e)).collect();
        let mut s = f.debug_struct("EtcdCoordinatorConfig");
        s.field("endpoints", &redacted)
            .field("namespace_prefix", &self.namespace_prefix)
            .field("owner_lease_ttl_secs", &self.owner_lease_ttl_secs)
            .field("optimistic_txn_retries", &self.optimistic_txn_retries)
            .field("max_children_per_op", &self.max_children_per_op);
        if let Some((user, _)) = &self.auth {
            s.field("auth_user", user);
            s.field("auth_password", &"[REDACTED]");
        }
        #[cfg(feature = "tls")]
        s.field("tls", &self.tls.as_ref().map(|_| "[configured]"));
        s.finish()
    }
}

impl EtcdCoordinatorConfig {
    /// Create a validated configuration with default persistence-tuning knobs.
    ///
    /// Defaults:
    /// - `owner_lease_ttl_secs = 60`
    /// - `optimistic_txn_retries = 8`
    /// - `max_children_per_op = 8`
    pub fn new<I, S>(
        endpoints: I,
        namespace_prefix: impl Into<String>,
    ) -> Result<Self, EtcdCoordinatorConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::new_with_tuning(
            endpoints,
            namespace_prefix,
            DEFAULT_OWNER_LEASE_TTL_SECS,
            DEFAULT_OPTIMISTIC_TXN_RETRIES,
            DEFAULT_MAX_CHILDREN_PER_OP,
        )
    }

    /// Create a validated configuration with explicit persistence-tuning
    /// values.
    ///
    /// Use this when the defaults are unsuitable — e.g., shorter TTLs for
    /// integration tests, higher retry budgets for high-contention
    /// environments, or wider fanout for large split operations.
    pub fn new_with_tuning<I, S>(
        endpoints: I,
        namespace_prefix: impl Into<String>,
        owner_lease_ttl_secs: i64,
        optimistic_txn_retries: usize,
        max_children_per_op: usize,
    ) -> Result<Self, EtcdCoordinatorConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let endpoints = endpoints
            .into_iter()
            .map(Into::into)
            .map(|endpoint| endpoint.trim().to_owned())
            .collect::<Vec<_>>();
        let namespace_prefix = namespace_prefix.into().trim().to_owned();

        let config = Self {
            endpoints,
            namespace_prefix,
            owner_lease_ttl_secs,
            optimistic_txn_retries,
            max_children_per_op,
            auth: None,
            #[cfg(feature = "tls")]
            tls: None,
        };
        config.validate()?;
        Ok(config)
    }

    /// Convenience configuration for a local single-node etcd at
    /// `http://127.0.0.1:2379` with namespace `/gossip/v1` and default
    /// tuning knobs.
    #[must_use]
    pub fn localhost() -> Self {
        Self::new(["http://127.0.0.1:2379"], "/gossip/v1")
            .expect("hard-coded localhost config must remain valid")
    }

    /// Parse a comma-separated endpoint string with default tuning knobs.
    ///
    /// Intended for consumption of environment variables and config file
    /// values where multiple endpoints are expressed as a single string
    /// (e.g. `ETCD_ENDPOINTS="http://a:2379,http://b:2379"`).
    ///
    /// Empty segments (e.g., trailing commas) are silently filtered out.
    /// Each remaining segment is trimmed of surrounding whitespace.
    pub fn from_endpoints_csv(
        endpoints_csv: &str,
        namespace_prefix: impl Into<String>,
    ) -> Result<Self, EtcdCoordinatorConfigError> {
        Self::from_endpoints_csv_with_tuning(
            endpoints_csv,
            namespace_prefix,
            DEFAULT_OWNER_LEASE_TTL_SECS,
            DEFAULT_OPTIMISTIC_TXN_RETRIES,
            DEFAULT_MAX_CHILDREN_PER_OP,
        )
    }

    /// Parse a comma-separated endpoint string with explicit persistence-tuning
    /// values.
    pub fn from_endpoints_csv_with_tuning(
        endpoints_csv: &str,
        namespace_prefix: impl Into<String>,
        owner_lease_ttl_secs: i64,
        optimistic_txn_retries: usize,
        max_children_per_op: usize,
    ) -> Result<Self, EtcdCoordinatorConfigError> {
        let endpoints = endpoints_csv
            .split(',')
            .map(str::trim)
            .filter(|endpoint| !endpoint.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Self::new_with_tuning(
            endpoints,
            namespace_prefix,
            owner_lease_ttl_secs,
            optimistic_txn_retries,
            max_children_per_op,
        )
    }

    /// Validate all configuration invariants.
    ///
    /// # Rules
    ///
    /// - At least one endpoint must be present.
    /// - Every endpoint must be non-empty and use `http://` or `https://`.
    /// - Namespace prefix must start with `/`, must not end with `/`
    ///   (unless it is exactly `"/"`), and must not contain `//`.
    /// - Owner lease TTL must be positive.
    /// - Optimistic txn retries must be at least 1.
    /// - Max children per split op must be between 1 and `MAX_SPLIT_CHILDREN`.
    pub fn validate(&self) -> Result<(), EtcdCoordinatorConfigError> {
        if self.endpoints.is_empty() {
            return Err(EtcdCoordinatorConfigError::NoEndpoints);
        }

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if endpoint.is_empty() {
                return Err(EtcdCoordinatorConfigError::EmptyEndpoint { index });
            }
            if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                return Err(EtcdCoordinatorConfigError::InvalidEndpointScheme { index });
            }
        }

        if self.namespace_prefix.is_empty() {
            return Err(EtcdCoordinatorConfigError::EmptyNamespacePrefix);
        }
        if !self.namespace_prefix.starts_with('/') {
            return Err(EtcdCoordinatorConfigError::NamespacePrefixMustStartWithSlash);
        }
        if self.namespace_prefix.ends_with('/') && self.namespace_prefix.len() > 1 {
            return Err(EtcdCoordinatorConfigError::NamespacePrefixMustNotEndWithSlash);
        }
        if self.namespace_prefix.contains("//") {
            return Err(EtcdCoordinatorConfigError::NamespacePrefixContainsDoubleSlash);
        }
        if self.owner_lease_ttl_secs <= 0 {
            return Err(EtcdCoordinatorConfigError::NonPositiveOwnerLeaseTtl);
        }
        if self.optimistic_txn_retries == 0 {
            return Err(EtcdCoordinatorConfigError::ZeroOptimisticTxnRetries);
        }
        if self.max_children_per_op == 0 {
            return Err(EtcdCoordinatorConfigError::ZeroMaxChildrenPerOp);
        }
        if self.max_children_per_op > MAX_SPLIT_CHILDREN {
            return Err(
                EtcdCoordinatorConfigError::MaxChildrenPerOpExceedsGlobalLimit {
                    requested: self.max_children_per_op,
                    global_max: MAX_SPLIT_CHILDREN,
                },
            );
        }

        Ok(())
    }

    /// The etcd member endpoints to contact.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// The etcd keyspace prefix under which all coordination keys are scoped.
    #[must_use]
    pub fn namespace_prefix(&self) -> &str {
        &self.namespace_prefix
    }

    /// Wall-clock etcd lease TTL used for ephemeral owner keys.
    #[must_use]
    pub fn owner_lease_ttl_secs(&self) -> i64 {
        self.owner_lease_ttl_secs
    }

    /// Maximum number of optimistic re-read/retry loops around a fenced etcd
    /// transaction.
    #[must_use]
    pub fn optimistic_txn_retries(&self) -> usize {
        self.optimistic_txn_retries
    }

    /// Maximum children the backend will publish in one atomic split
    /// operation.
    ///
    /// Higher values increase the `split_replace` transaction write count
    /// as `3 + 2 * children`, so callers must keep this within the etcd
    /// cluster's configured txn-op budget.
    #[must_use]
    pub fn max_children_per_op(&self) -> usize {
        self.max_children_per_op
    }

    /// Optional authentication credentials (username, password).
    #[must_use]
    pub fn auth(&self) -> Option<(&str, &str)> {
        self.auth
            .as_ref()
            .map(|(user, pass)| (user.as_str(), pass.as_str()))
    }

    /// Optional TLS configuration for encrypted connections.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn tls(&self) -> Option<&etcd_client::TlsOptions> {
        self.tls.as_ref()
    }

    /// Set authentication credentials for the etcd connection.
    #[must_use]
    pub fn with_auth(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((user.into(), password.into()));
        self
    }

    /// Set TLS configuration for encrypted etcd connections.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, tls: etcd_client::TlsOptions) -> Self {
        self.tls = Some(tls);
        self
    }
}

impl Default for EtcdCoordinatorConfig {
    fn default() -> Self {
        Self::localhost()
    }
}

/// Configuration validation errors for [`EtcdCoordinatorConfig`].
///
/// Each variant pinpoints a single invalid parameter, with positional
/// indexes for multi-valued fields (endpoints). All checks run eagerly
/// at construction time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EtcdCoordinatorConfigError {
    /// No endpoints were provided (the list is empty after filtering).
    NoEndpoints,
    /// The endpoint at `index` resolved to an empty string after trimming.
    EmptyEndpoint { index: usize },
    /// The endpoint at `index` does not use `http://` or `https://`.
    InvalidEndpointScheme { index: usize },
    /// The namespace prefix is empty after trimming.
    EmptyNamespacePrefix,
    /// The namespace prefix must start with `/` to form absolute etcd paths.
    NamespacePrefixMustStartWithSlash,
    /// The namespace prefix must not end with `/` (unless it is exactly `"/"`).
    NamespacePrefixMustNotEndWithSlash,
    /// The namespace prefix contains consecutive slashes (`//`), which
    /// would create invisible empty path segments.
    NamespacePrefixContainsDoubleSlash,
    /// `owner_lease_ttl_secs` must be positive (> 0).
    NonPositiveOwnerLeaseTtl,
    /// `optimistic_txn_retries` must be at least 1.
    ZeroOptimisticTxnRetries,
    /// `max_children_per_op` must be at least 1.
    ZeroMaxChildrenPerOp,
    /// `max_children_per_op` cannot exceed the global split limit.
    MaxChildrenPerOpExceedsGlobalLimit { requested: usize, global_max: usize },
}

impl fmt::Display for EtcdCoordinatorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEndpoints => f.write_str("at least one etcd endpoint is required"),
            Self::EmptyEndpoint { index } => {
                write!(f, "etcd endpoint at index {index} must not be empty")
            }
            Self::InvalidEndpointScheme { index } => {
                write!(
                    f,
                    "etcd endpoint at index {index} has invalid scheme (expected http:// or https://)"
                )
            }
            Self::EmptyNamespacePrefix => f.write_str("namespace_prefix must not be empty"),
            Self::NamespacePrefixMustStartWithSlash => {
                f.write_str("namespace_prefix must start with '/'")
            }
            Self::NamespacePrefixMustNotEndWithSlash => {
                f.write_str("namespace_prefix must not end with '/' unless it is exactly '/'")
            }
            Self::NamespacePrefixContainsDoubleSlash => {
                f.write_str("namespace_prefix must not contain consecutive slashes '//'")
            }
            Self::NonPositiveOwnerLeaseTtl => f.write_str("owner_lease_ttl_secs must be > 0"),
            Self::ZeroOptimisticTxnRetries => f.write_str("optimistic_txn_retries must be > 0"),
            Self::ZeroMaxChildrenPerOp => f.write_str("max_children_per_op must be > 0"),
            Self::MaxChildrenPerOpExceedsGlobalLimit {
                requested,
                global_max,
            } => write!(
                f,
                "max_children_per_op ({requested}) exceeds global MAX_SPLIT_CHILDREN ({global_max})",
            ),
        }
    }
}

impl std::error::Error for EtcdCoordinatorConfigError {}
