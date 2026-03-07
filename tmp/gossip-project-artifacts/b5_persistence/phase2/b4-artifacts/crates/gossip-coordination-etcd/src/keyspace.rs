use std::fmt;

use gossip_contracts::identity::{RunId, ShardId, TenantId};

/// Validation errors for [`EtcdKeyspace`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdKeyspaceError {
    EmptyPrefix,
    PrefixMustStartWithSlash,
    PrefixMustNotEndWithSlash,
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
        }
    }
}

impl std::error::Error for EtcdKeyspaceError {}

/// Deterministic builder for the etcd coordination key layout.
///
/// All keys are ASCII paths rooted at a caller-provided namespace prefix, for
/// example `/gossip/v1`.
///
/// Layout:
/// - `{prefix}/tenants/{tenant_hex}/runs/{run_hex}` -> `RunRecord`
/// - `{prefix}/tenants/{tenant_hex}/runs/{run_hex}/shards/{shard_hex}` -> `ShardRecord`
/// - `{prefix}/tenants/{tenant_hex}/runs/{run_hex}/shards/{shard_hex}/owner` -> owner lease key
/// - `{prefix}/tenants/{tenant_hex}/runs_active/{run_hex}` -> active-run index key
/// - `{prefix}/tenants/{tenant_hex}/runs/{run_hex}/shards_active/{shard_hex}` -> active-shard index key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtcdKeyspace {
    prefix: String,
}

impl EtcdKeyspace {
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
        Ok(Self { prefix })
    }

    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    #[must_use]
    pub fn tenants_prefix(&self) -> String {
        format!("{}/tenants", self.prefix)
    }

    #[must_use]
    pub fn tenant_prefix(&self, tenant: TenantId) -> String {
        format!("{}/{}", self.tenants_prefix(), tenant_hex(tenant))
    }

    #[must_use]
    pub fn runs_prefix(&self, tenant: TenantId) -> String {
        format!("{}/runs", self.tenant_prefix(tenant))
    }

    /// Key for the authoritative `RunRecord` blob.
    #[must_use]
    pub fn run_record_key(&self, tenant: TenantId, run: RunId) -> String {
        format!("{}/{}", self.runs_prefix(tenant), run_hex(run))
    }

    /// Prefix under which shard records for a run live.
    #[must_use]
    pub fn run_shards_prefix(&self, tenant: TenantId, run: RunId) -> String {
        format!("{}/shards", self.run_record_key(tenant, run))
    }

    /// Prefix scan root that includes both shard records and their `/owner` keys.
    #[must_use]
    pub fn shard_records_scan_prefix(&self, tenant: TenantId, run: RunId) -> String {
        self.run_shards_prefix(tenant, run)
    }

    /// Key for the authoritative `ShardRecord` blob.
    #[must_use]
    pub fn shard_record_key(&self, tenant: TenantId, run: RunId, shard: ShardId) -> String {
        format!("{}/{}", self.run_shards_prefix(tenant, run), shard_hex(shard))
    }

    /// Ephemeral owner lease key for a shard.
    #[must_use]
    pub fn shard_owner_key(&self, tenant: TenantId, run: RunId, shard: ShardId) -> String {
        format!("{}/owner", self.shard_record_key(tenant, run, shard))
    }

    #[must_use]
    pub fn runs_active_prefix(&self, tenant: TenantId) -> String {
        format!("{}/runs_active", self.tenant_prefix(tenant))
    }

    #[must_use]
    pub fn run_active_index_key(&self, tenant: TenantId, run: RunId) -> String {
        format!("{}/{}", self.runs_active_prefix(tenant), run_hex(run))
    }

    #[must_use]
    pub fn shards_active_prefix(&self, tenant: TenantId, run: RunId) -> String {
        format!("{}/shards_active", self.run_record_key(tenant, run))
    }

    #[must_use]
    pub fn active_shard_index_key(&self, tenant: TenantId, run: RunId, shard: ShardId) -> String {
        format!("{}/{}", self.shards_active_prefix(tenant, run), shard_hex(shard))
    }
}

fn tenant_hex(tenant: TenantId) -> String {
    encode_hex(tenant.as_bytes())
}

fn run_hex(run: RunId) -> String {
    format!("{:016x}", run.as_raw())
}

fn shard_hex(shard: ShardId) -> String {
    format!("{:016x}", shard.as_raw())
}

fn encode_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
