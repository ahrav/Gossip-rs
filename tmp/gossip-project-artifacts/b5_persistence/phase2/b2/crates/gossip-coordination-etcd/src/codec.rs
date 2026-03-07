use std::fmt;

use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, PooledCursor, PooledShardSpec, PooledSpawned, ShardSpecRef};
use gossip_contracts::identity::{FenceEpoch, LogicalTime, RunId, ShardId, TenantId, WorkerId};
use gossip_coordination::{
    LeaseHolder, OpKind, OpLogEntry, OpResult, ParkReason, RunConfig, RunOpKind, RunOpLogEntry,
    RunOpResult, RunRecord, RunStatus, ShardRecord, ShardStatus,
};
use gossip_stdx::{ByteSlab, RingBuffer, SlabFull};

const VERSION_PREFIX_V1: &[u8; 2] = b"v1";

/// Blob kind tag in the versioned etcd payload header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlobKind {
    RunRecord = 1,
    ShardRecord = 2,
    ShardOwner = 3,
}

impl BlobKind {
    fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::RunRecord),
            2 => Some(Self::ShardRecord),
            3 => Some(Self::ShardOwner),
            _ => None,
        }
    }

    fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Deterministic decode/encode errors for versioned etcd blobs.
#[derive(Debug)]
#[non_exhaustive]
pub enum EtcdCodecError {
    Truncated { needed: usize, remaining: usize },
    InvalidVersionPrefix { actual: [u8; 2] },
    InvalidBlobKind { actual: u8 },
    UnexpectedBlobKind { expected: BlobKind, actual: BlobKind },
    InvalidBool { actual: u8 },
    InvalidEnum { ty: &'static str, actual: u8 },
    InvalidSpec { message: String },
    InvalidCursor { message: String },
    SlabFull,
    TrailingBytes { remaining: usize },
    InvariantViolation { kind: &'static str, detail: &'static str },
}

impl fmt::Display for EtcdCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, remaining } => {
                write!(f, "truncated blob: needed {needed} bytes, only {remaining} remaining")
            }
            Self::InvalidVersionPrefix { actual } => {
                write!(f, "invalid version prefix: expected {:?}, got {:?}", VERSION_PREFIX_V1, actual)
            }
            Self::InvalidBlobKind { actual } => write!(f, "invalid blob kind tag: {actual}"),
            Self::UnexpectedBlobKind { expected, actual } => {
                write!(f, "unexpected blob kind: expected {expected:?}, got {actual:?}")
            }
            Self::InvalidBool { actual } => write!(f, "invalid bool tag: {actual}"),
            Self::InvalidEnum { ty, actual } => write!(f, "invalid {ty} discriminant: {actual}"),
            Self::InvalidSpec { message } => write!(f, "invalid shard spec in blob: {message}"),
            Self::InvalidCursor { message } => write!(f, "invalid cursor in blob: {message}"),
            Self::SlabFull => f.write_str("insufficient slab capacity while decoding shard record"),
            Self::TrailingBytes { remaining } => {
                write!(f, "blob has {remaining} trailing bytes after decode")
            }
            Self::InvariantViolation { kind, detail } => {
                write!(f, "decoded {kind} violates invariant: {detail}")
            }
        }
    }
}

impl std::error::Error for EtcdCodecError {}

/// Deterministic owner-key payload stored under the ephemeral `/owner` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerLeaseValueV1 {
    pub worker: WorkerId,
    pub fence: FenceEpoch,
}

impl From<SlabFull> for EtcdCodecError {
    fn from(_: SlabFull) -> Self {
        Self::SlabFull
    }
}

/// Encode a `RunRecord` using the explicit v1 blob format.
#[must_use]
pub fn encode_run_record_v1(record: &RunRecord) -> Vec<u8> {
    let owned = OwnedRunRecord::from_record(record);
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(VERSION_PREFIX_V1);
    out.push(BlobKind::RunRecord.as_u8());
    owned.encode_into(&mut out);
    out
}

/// Decode a v1 `RunRecord` blob.
pub fn decode_run_record_v1(blob: &[u8]) -> Result<RunRecord, EtcdCodecError> {
    let mut dec = Decoder::new(blob);
    dec.expect_header(BlobKind::RunRecord)?;
    let owned = OwnedRunRecord::decode(&mut dec)?;
    dec.finish()?;
    owned.into_record()
}

/// Encode a `ShardRecord` using the explicit v1 blob format.
#[must_use]
pub fn encode_shard_record_v1(record: &ShardRecord, slab: &ByteSlab) -> Vec<u8> {
    let owned = OwnedShardRecord::from_record(record, slab);
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(VERSION_PREFIX_V1);
    out.push(BlobKind::ShardRecord.as_u8());
    owned.encode_into(&mut out);
    out
}

/// Decode a v1 `ShardRecord` blob, allocating pooled fields into `slab`.
pub fn decode_shard_record_v1(
    blob: &[u8],
    slab: &mut ByteSlab,
) -> Result<ShardRecord, EtcdCodecError> {
    let mut dec = Decoder::new(blob);
    dec.expect_header(BlobKind::ShardRecord)?;
    let owned = OwnedShardRecord::decode(&mut dec)?;
    dec.finish()?;
    owned.into_record(slab)
}

/// Encode the ephemeral shard-owner value using the explicit v1 blob format.
#[must_use]
pub fn encode_owner_value_v1(worker: WorkerId, fence: FenceEpoch) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + 8 + 8);
    out.extend_from_slice(VERSION_PREFIX_V1);
    out.push(BlobKind::ShardOwner.as_u8());
    put_u64(&mut out, worker.as_raw());
    put_u64(&mut out, fence.as_raw());
    out
}

/// Decode a v1 shard-owner value blob.
pub fn decode_owner_value_v1(blob: &[u8]) -> Result<OwnerLeaseValueV1, EtcdCodecError> {
    let mut dec = Decoder::new(blob);
    dec.expect_header(BlobKind::ShardOwner)?;
    let worker = WorkerId::from_raw(dec.read_u64()?);
    let fence = FenceEpoch::from_raw(dec.read_u64()?);
    dec.finish()?;
    Ok(OwnerLeaseValueV1 { worker, fence })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedRunRecord {
    tenant: TenantId,
    run: RunId,
    cursor_semantics: CursorSemantics,
    lease_duration: u64,
    max_shard_retries: Option<u32>,
    status: RunStatus,
    created_at: LogicalTime,
    completed_at: Option<LogicalTime>,
    root_shards: Vec<ShardId>,
    op_log: Vec<OwnedRunOpLogEntry>,
}

impl OwnedRunRecord {
    fn from_record(record: &RunRecord) -> Self {
        Self {
            tenant: record.tenant,
            run: record.run,
            cursor_semantics: record.config.cursor_semantics(),
            lease_duration: record.config.lease_duration(),
            max_shard_retries: record.config.max_shard_retries(),
            status: record.status,
            created_at: record.created_at,
            completed_at: record.completed_at,
            root_shards: record.root_shards.clone(),
            op_log: record.op_log.iter().map(OwnedRunOpLogEntry::from_entry).collect(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_tenant(out, self.tenant);
        put_u64(out, self.run.as_raw());
        put_u8(out, self.cursor_semantics.as_u8());
        put_u64(out, self.lease_duration);
        put_opt_u32(out, self.max_shard_retries);
        put_u8(out, self.status.as_u8());
        put_u64(out, self.created_at.as_raw());
        put_opt_u64(out, self.completed_at.map(|t| t.as_raw()));
        put_len(out, self.root_shards.len());
        for shard in &self.root_shards {
            put_u64(out, shard.as_raw());
        }
        put_len(out, self.op_log.len());
        for entry in &self.op_log {
            entry.encode_into(out);
        }
    }

    fn decode(dec: &mut Decoder<'_>) -> Result<Self, EtcdCodecError> {
        let tenant = dec.read_tenant()?;
        let run = RunId::from_raw(dec.read_u64()?);
        let cursor_semantics = CursorSemantics::from_u8(dec.read_u8()?)
            .ok_or(EtcdCodecError::InvalidEnum {
                ty: "CursorSemantics",
                actual: dec.last_u8,
            })?;
        let lease_duration = dec.read_u64()?;
        let max_shard_retries = dec.read_opt_u32()?;
        let status_raw = dec.read_u8()?;
        let status = RunStatus::from_u8(status_raw).ok_or(EtcdCodecError::InvalidEnum {
            ty: "RunStatus",
            actual: status_raw,
        })?;
        let created_at = LogicalTime::from_raw(dec.read_u64()?);
        let completed_at = dec.read_opt_u64()?.map(LogicalTime::from_raw);

        let root_len = dec.read_len()?;
        let mut root_shards = Vec::with_capacity(root_len);
        for _ in 0..root_len {
            root_shards.push(ShardId::from_raw(dec.read_u64()?));
        }

        let op_len = dec.read_len()?;
        let mut op_log = Vec::with_capacity(op_len);
        for _ in 0..op_len {
            op_log.push(OwnedRunOpLogEntry::decode(dec)?);
        }

        let owned = Self {
            tenant,
            run,
            cursor_semantics,
            lease_duration,
            max_shard_retries,
            status,
            created_at,
            completed_at,
            root_shards,
            op_log,
        };
        owned.validate()?;
        Ok(owned)
    }

    fn into_record(self) -> Result<RunRecord, EtcdCodecError> {
        self.validate()?;
        let config = RunConfig::try_new(
            self.cursor_semantics,
            self.lease_duration,
            self.max_shard_retries,
        )
        .map_err(|err| EtcdCodecError::InvariantViolation {
            kind: "RunRecord",
            detail: match err {
                gossip_coordination::RunConfigError::ZeroLeaseDuration => {
                    "lease_duration must be > 0"
                }
            },
        })?;

        let mut op_log = RingBuffer::<RunOpLogEntry, { RunRecord::OP_LOG_CAP }>::new();
        for entry in self.op_log {
            op_log.push_back_overwrite(entry.into_entry()?);
        }

        let record = RunRecord {
            tenant: self.tenant,
            run: self.run,
            config,
            status: self.status,
            created_at: self.created_at,
            completed_at: self.completed_at,
            root_shards: self.root_shards,
            op_log,
        };
        Ok(record)
    }

    fn validate(&self) -> Result<(), EtcdCodecError> {
        if self.created_at <= LogicalTime::ZERO {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunRecord",
                detail: "created_at must be > ZERO",
            });
        }
        if self.lease_duration == 0 {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunRecord",
                detail: "lease_duration must be > 0",
            });
        }
        if self.status == RunStatus::Active && self.root_shards.is_empty() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunRecord",
                detail: "Active run must have at least one root shard",
            });
        }
        if self.status == RunStatus::Initializing && !self.root_shards.is_empty() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunRecord",
                detail: "Initializing run must not have root shards",
            });
        }
        if self.status.is_terminal() != self.completed_at.is_some() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunRecord",
                detail: "completed_at presence must match terminal status",
            });
        }
        if let Some(completed_at) = self.completed_at {
            if completed_at < self.created_at {
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "completed_at must be >= created_at",
                });
            }
        }
        if self.op_log.len() > RunRecord::OP_LOG_CAP {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunRecord",
                detail: "op_log exceeds cap",
            });
        }
        for i in 0..self.root_shards.len() {
            for j in (i + 1)..self.root_shards.len() {
                if self.root_shards[i] == self.root_shards[j] {
                    return Err(EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "root_shards must not contain duplicates",
                    });
                }
            }
        }
        for i in 0..self.op_log.len() {
            for j in (i + 1)..self.op_log.len() {
                if self.op_log[i].op_id == self.op_log[j].op_id {
                    return Err(EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "op_log must not contain duplicate OpId values",
                    });
                }
            }
            if i > 0 && self.op_log[i].executed_at < self.op_log[i - 1].executed_at {
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "op_log timestamps must be non-decreasing",
                });
            }
            self.op_log[i].validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedRunOpLogEntry {
    op_id: gossip_contracts::identity::OpId,
    kind: RunOpKind,
    payload_hash: u64,
    executed_at: LogicalTime,
    result: OwnedRunOpResult,
}

impl OwnedRunOpLogEntry {
    fn from_entry(entry: &RunOpLogEntry) -> Self {
        Self {
            op_id: entry.op_id(),
            kind: entry.kind(),
            payload_hash: entry.payload_hash(),
            executed_at: entry.executed_at(),
            result: OwnedRunOpResult::from_result(entry.result()),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_u64(out, self.op_id.as_raw());
        put_u8(out, self.kind.as_u8());
        put_u64(out, self.payload_hash);
        put_u64(out, self.executed_at.as_raw());
        self.result.encode_into(out);
    }

    fn decode(dec: &mut Decoder<'_>) -> Result<Self, EtcdCodecError> {
        let op_id = gossip_contracts::identity::OpId::from_raw(dec.read_u64()?);
        let kind_raw = dec.read_u8()?;
        let kind = RunOpKind::from_u8(kind_raw).ok_or(EtcdCodecError::InvalidEnum {
            ty: "RunOpKind",
            actual: kind_raw,
        })?;
        let payload_hash = dec.read_u64()?;
        let executed_at = LogicalTime::from_raw(dec.read_u64()?);
        let result = OwnedRunOpResult::decode(dec)?;
        let owned = Self {
            op_id,
            kind,
            payload_hash,
            executed_at,
            result,
        };
        owned.validate()?;
        Ok(owned)
    }

    fn into_entry(self) -> Result<RunOpLogEntry, EtcdCodecError> {
        self.validate()?;
        Ok(RunOpLogEntry::new(
            self.op_id,
            self.kind,
            self.payload_hash,
            self.executed_at,
            self.result.into_result(),
        ))
    }

    fn validate(&self) -> Result<(), EtcdCodecError> {
        if self.payload_hash == 0 {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunOpLogEntry",
                detail: "payload_hash must be non-zero",
            });
        }
        if self.executed_at <= LogicalTime::ZERO {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "RunOpLogEntry",
                detail: "executed_at must be > ZERO",
            });
        }
        match (&self.kind, &self.result) {
            (RunOpKind::RegisterShards, OwnedRunOpResult::RegisteredShards { .. }) => {}
            (RunOpKind::RegisterShards, OwnedRunOpResult::Ack) => {
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "RunOpLogEntry",
                    detail: "RegisterShards must use RegisteredShards result",
                });
            }
            (_, OwnedRunOpResult::Ack) => {}
            (_, OwnedRunOpResult::RegisteredShards { .. }) => {
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "RunOpLogEntry",
                    detail: "non-RegisterShards entry must use Ack result",
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum OwnedRunOpResult {
    RegisteredShards { shard_ids: Vec<ShardId> },
    Ack,
}

impl OwnedRunOpResult {
    fn from_result(result: &RunOpResult) -> Self {
        match result {
            RunOpResult::RegisteredShards { shard_ids } => Self::RegisteredShards {
                shard_ids: shard_ids.to_vec(),
            },
            RunOpResult::Ack => Self::Ack,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::RegisteredShards { shard_ids } => {
                put_u8(out, 1);
                put_len(out, shard_ids.len());
                for shard in shard_ids {
                    put_u64(out, shard.as_raw());
                }
            }
            Self::Ack => put_u8(out, 2),
        }
    }

    fn decode(dec: &mut Decoder<'_>) -> Result<Self, EtcdCodecError> {
        match dec.read_u8()? {
            1 => {
                let len = dec.read_len()?;
                let mut shard_ids = Vec::with_capacity(len);
                for _ in 0..len {
                    shard_ids.push(ShardId::from_raw(dec.read_u64()?));
                }
                Ok(Self::RegisteredShards { shard_ids })
            }
            2 => Ok(Self::Ack),
            actual => Err(EtcdCodecError::InvalidEnum {
                ty: "RunOpResultTag",
                actual,
            }),
        }
    }

    fn into_result(self) -> RunOpResult {
        match self {
            Self::RegisteredShards { shard_ids } => RunOpResult::RegisteredShards {
                shard_ids: shard_ids.into_boxed_slice(),
            },
            Self::Ack => RunOpResult::Ack,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedShardRecord {
    tenant: TenantId,
    run: RunId,
    shard: ShardId,
    status: ShardStatus,
    park_reason: Option<ParkReason>,
    key_range_start: Vec<u8>,
    key_range_end: Vec<u8>,
    metadata: Vec<u8>,
    cursor_last_key: Option<Vec<u8>>,
    cursor_token: Option<Vec<u8>>,
    cursor_semantics: CursorSemantics,
    lease_owner: Option<WorkerId>,
    lease_deadline: Option<LogicalTime>,
    fence_epoch: FenceEpoch,
    parent: Option<ShardId>,
    spawned: Vec<ShardId>,
    op_log: Vec<OwnedShardOpLogEntry>,
}

impl OwnedShardRecord {
    fn from_record(record: &ShardRecord, slab: &ByteSlab) -> Self {
        let spec = record.spec.as_spec_ref(slab);
        Self {
            tenant: record.tenant,
            run: record.run,
            shard: record.shard,
            status: record.status,
            park_reason: record.park_reason,
            key_range_start: spec.key_range_start().to_vec(),
            key_range_end: spec.key_range_end().to_vec(),
            metadata: spec.metadata().to_vec(),
            cursor_last_key: record.cursor.last_key(slab).map(ToOwned::to_owned),
            cursor_token: record.cursor.token(slab).map(ToOwned::to_owned),
            cursor_semantics: record.cursor_semantics,
            lease_owner: record.lease.map(|lease| lease.owner()),
            lease_deadline: record.lease.map(|lease| lease.deadline()),
            fence_epoch: record.fence_epoch,
            parent: record.parent,
            spawned: record.spawned.iter(slab).collect(),
            op_log: record.op_log.iter().map(OwnedShardOpLogEntry::from_entry).collect(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_tenant(out, self.tenant);
        put_u64(out, self.run.as_raw());
        put_u64(out, self.shard.as_raw());
        put_u8(out, self.status.as_u8());
        put_opt_u8(out, self.park_reason.map(ParkReason::as_u8));
        put_bytes(out, &self.key_range_start);
        put_bytes(out, &self.key_range_end);
        put_bytes(out, &self.metadata);
        put_opt_bytes(out, self.cursor_last_key.as_deref());
        put_opt_bytes(out, self.cursor_token.as_deref());
        put_u8(out, self.cursor_semantics.as_u8());
        match (self.lease_owner, self.lease_deadline) {
            (Some(owner), Some(deadline)) => {
                put_bool(out, true);
                put_u64(out, owner.as_raw());
                put_u64(out, deadline.as_raw());
            }
            (None, None) => put_bool(out, false),
            (Some(_), None) | (None, Some(_)) => {
                panic!("OwnedShardRecord::encode_into called with partial lease state")
            }
        }
        put_u64(out, self.fence_epoch.as_raw());
        put_opt_u64(out, self.parent.map(|p| p.as_raw()));
        put_len(out, self.spawned.len());
        for spawned in &self.spawned {
            put_u64(out, spawned.as_raw());
        }
        put_len(out, self.op_log.len());
        for entry in &self.op_log {
            entry.encode_into(out);
        }
    }

    fn decode(dec: &mut Decoder<'_>) -> Result<Self, EtcdCodecError> {
        let tenant = dec.read_tenant()?;
        let run = RunId::from_raw(dec.read_u64()?);
        let shard = ShardId::from_raw(dec.read_u64()?);
        let status_raw = dec.read_u8()?;
        let status = ShardStatus::from_u8(status_raw).ok_or(EtcdCodecError::InvalidEnum {
            ty: "ShardStatus",
            actual: status_raw,
        })?;
        let park_reason = match dec.read_opt_u8()? {
            Some(raw) => Some(ParkReason::from_u8(raw).ok_or(EtcdCodecError::InvalidEnum {
                ty: "ParkReason",
                actual: raw,
            })?),
            None => None,
        };
        let key_range_start = dec.read_vec()?;
        let key_range_end = dec.read_vec()?;
        let metadata = dec.read_vec()?;
        let cursor_last_key = dec.read_opt_vec()?;
        let cursor_token = dec.read_opt_vec()?;
        let cursor_semantics_raw = dec.read_u8()?;
        let cursor_semantics = CursorSemantics::from_u8(cursor_semantics_raw)
            .ok_or(EtcdCodecError::InvalidEnum {
                ty: "CursorSemantics",
                actual: cursor_semantics_raw,
            })?;
        let has_lease = dec.read_bool()?;
        let (lease_owner, lease_deadline) = if has_lease {
            (
                Some(WorkerId::from_raw(dec.read_u64()?)),
                Some(LogicalTime::from_raw(dec.read_u64()?)),
            )
        } else {
            (None, None)
        };
        let fence_epoch = FenceEpoch::from_raw(dec.read_u64()?);
        let parent = dec.read_opt_u64()?.map(ShardId::from_raw);
        let spawned_len = dec.read_len()?;
        let mut spawned = Vec::with_capacity(spawned_len);
        for _ in 0..spawned_len {
            spawned.push(ShardId::from_raw(dec.read_u64()?));
        }
        let op_len = dec.read_len()?;
        let mut op_log = Vec::with_capacity(op_len);
        for _ in 0..op_len {
            op_log.push(OwnedShardOpLogEntry::decode(dec)?);
        }

        let owned = Self {
            tenant,
            run,
            shard,
            status,
            park_reason,
            key_range_start,
            key_range_end,
            metadata,
            cursor_last_key,
            cursor_token,
            cursor_semantics,
            lease_owner,
            lease_deadline,
            fence_epoch,
            parent,
            spawned,
            op_log,
        };
        owned.validate()?;
        Ok(owned)
    }

    fn into_record(self, slab: &mut ByteSlab) -> Result<ShardRecord, EtcdCodecError> {
        self.validate()?;

        let spec_ref = ShardSpecRef::try_with_range_and_metadata(
            &self.key_range_start,
            &self.key_range_end,
            &self.metadata,
        )
        .map_err(|err| EtcdCodecError::InvalidSpec {
            message: err.to_string(),
        })?;
        let pooled_spec = PooledShardSpec::from_spec_ref(spec_ref, slab)?;

        let cursor_update = match (&self.cursor_last_key, &self.cursor_token) {
            (None, None) => CursorUpdate::initial(),
            (Some(last_key), None) => {
                CursorUpdate::try_with_last_key(last_key).map_err(|err| EtcdCodecError::InvalidCursor {
                    message: err.to_string(),
                })?
            }
            (Some(last_key), Some(token)) => {
                CursorUpdate::try_with_token(last_key, token).map_err(|err| EtcdCodecError::InvalidCursor {
                    message: err.to_string(),
                })?
            }
            (None, Some(_)) => {
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "cursor token without cursor last_key is invalid",
                });
            }
        };

        let mut pooled_cursor = match PooledCursor::from_update(&cursor_update, slab) {
            Ok(cursor) => cursor,
            Err(err) => {
                pooled_spec.deallocate(slab);
                return Err(err.into());
            }
        };

        let mut pooled_spawned = PooledSpawned::new();
        if !self.spawned.is_empty() {
            match pooled_spawned.allocate_appended_slot(&self.spawned, slab) {
                Ok((slot, len)) => pooled_spawned.install_slot(slot, len, slab),
                Err(err) => {
                    pooled_cursor.release_fields(slab);
                    pooled_spec.deallocate(slab);
                    return Err(err.into());
                }
            }
        }

        let mut op_log = RingBuffer::<OpLogEntry, { ShardRecord::OP_LOG_CAP }>::new();
        for entry in self.op_log {
            let entry = match entry.into_entry() {
                Ok(entry) => entry,
                Err(err) => {
                    pooled_spawned.release_fields(slab);
                    pooled_cursor.release_fields(slab);
                    pooled_spec.deallocate(slab);
                    return Err(err);
                }
            };
            op_log.push_back_overwrite(entry);
        }

        let lease = match (self.lease_owner, self.lease_deadline) {
            (Some(owner), Some(deadline)) => Some(LeaseHolder::new(owner, deadline)),
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                pooled_spawned.release_fields(slab);
                pooled_cursor.release_fields(slab);
                pooled_spec.deallocate(slab);
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "lease owner and deadline must either both be present or both absent",
                });
            }
        };

        let record = ShardRecord {
            tenant: self.tenant,
            run: self.run,
            shard: self.shard,
            status: self.status,
            park_reason: self.park_reason,
            spec: pooled_spec,
            cursor: pooled_cursor,
            cursor_semantics: self.cursor_semantics,
            lease,
            fence_epoch: self.fence_epoch,
            parent: self.parent,
            spawned: pooled_spawned,
            op_log,
        };
        Ok(record)
    }

    fn validate(&self) -> Result<(), EtcdCodecError> {
        if self.status == ShardStatus::Parked && self.park_reason.is_none() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "Parked shard must have park_reason",
            });
        }
        if self.status != ShardStatus::Parked && self.park_reason.is_some() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "non-Parked shard must not have park_reason",
            });
        }
        if self.status.is_terminal() && self.lease_owner.is_some() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "terminal shard must not have a lease",
            });
        }
        if self.lease_owner.is_some() != self.lease_deadline.is_some() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "lease owner and deadline must either both be present or both absent",
            });
        }
        if let Some(deadline) = self.lease_deadline {
            if deadline <= LogicalTime::ZERO {
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "lease deadline must be > ZERO when present",
                });
            }
        }
        if self.fence_epoch < FenceEpoch::INITIAL {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "fence_epoch must be >= INITIAL",
            });
        }
        if self.cursor_last_key.is_none() && self.cursor_token.is_some() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "cursor token without cursor last_key is invalid",
            });
        }
        if self.status == ShardStatus::Split && self.spawned.is_empty() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "Split shard must have spawned children",
            });
        }
        if self.parent.is_some() != self.shard.is_derived() {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "parent presence must match shard derived-bit",
            });
        }
        for spawned in &self.spawned {
            if !spawned.is_derived() {
                return Err(EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "all spawned shard ids must be derived",
                });
            }
        }
        if self.op_log.len() > ShardRecord::OP_LOG_CAP {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "op_log exceeds cap",
            });
        }
        if self.spawned.len() > gossip_contracts::coordination::MAX_SPAWNED_PER_SHARD {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "spawned exceeds MAX_SPAWNED_PER_SHARD",
            });
        }
        for i in 0..self.op_log.len() {
            for j in (i + 1)..self.op_log.len() {
                if self.op_log[i].op_id == self.op_log[j].op_id {
                    return Err(EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "op_log must not contain duplicate OpId values",
                    });
                }
            }
            self.op_log[i].validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedShardOpLogEntry {
    op_id: gossip_contracts::identity::OpId,
    kind: OpKind,
    result: OpResult,
    payload_hash: u64,
    executed_at: LogicalTime,
}

impl OwnedShardOpLogEntry {
    fn from_entry(entry: &OpLogEntry) -> Self {
        Self {
            op_id: entry.op_id(),
            kind: entry.kind(),
            result: entry.result(),
            payload_hash: entry.payload_hash(),
            executed_at: entry.executed_at(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        put_u64(out, self.op_id.as_raw());
        put_u8(out, self.kind.as_u8());
        put_u8(out, self.result.as_u8());
        put_u64(out, self.payload_hash);
        put_u64(out, self.executed_at.as_raw());
    }

    fn decode(dec: &mut Decoder<'_>) -> Result<Self, EtcdCodecError> {
        let op_id = gossip_contracts::identity::OpId::from_raw(dec.read_u64()?);
        let kind_raw = dec.read_u8()?;
        let kind = OpKind::from_u8(kind_raw).ok_or(EtcdCodecError::InvalidEnum {
            ty: "OpKind",
            actual: kind_raw,
        })?;
        let result_raw = dec.read_u8()?;
        let result = OpResult::from_u8(result_raw).ok_or(EtcdCodecError::InvalidEnum {
            ty: "OpResult",
            actual: result_raw,
        })?;
        let payload_hash = dec.read_u64()?;
        let executed_at = LogicalTime::from_raw(dec.read_u64()?);
        let owned = Self {
            op_id,
            kind,
            result,
            payload_hash,
            executed_at,
        };
        owned.validate()?;
        Ok(owned)
    }

    fn into_entry(self) -> Result<OpLogEntry, EtcdCodecError> {
        self.validate()?;
        Ok(OpLogEntry::new(
            self.op_id,
            self.kind,
            self.result,
            self.payload_hash,
            self.executed_at,
        ))
    }

    fn validate(&self) -> Result<(), EtcdCodecError> {
        if self.payload_hash == 0 {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "OpLogEntry",
                detail: "payload_hash must be non-zero",
            });
        }
        if self.executed_at <= LogicalTime::ZERO {
            return Err(EtcdCodecError::InvariantViolation {
                kind: "OpLogEntry",
                detail: "executed_at must be > ZERO",
            });
        }
        Ok(())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    last_u8: u8,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            last_u8: 0,
        }
    }

    fn expect_header(&mut self, expected_kind: BlobKind) -> Result<(), EtcdCodecError> {
        let prefix = self.read_exact(2)?;
        let actual = <[u8; 2]>::try_from(prefix).expect("slice length checked");
        if &actual != VERSION_PREFIX_V1 {
            return Err(EtcdCodecError::InvalidVersionPrefix { actual });
        }
        let kind_raw = self.read_u8()?;
        let actual_kind = BlobKind::from_u8(kind_raw)
            .ok_or(EtcdCodecError::InvalidBlobKind { actual: kind_raw })?;
        if actual_kind != expected_kind {
            return Err(EtcdCodecError::UnexpectedBlobKind {
                expected: expected_kind,
                actual: actual_kind,
            });
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), EtcdCodecError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining != 0 {
            return Err(EtcdCodecError::TrailingBytes { remaining });
        }
        Ok(())
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], EtcdCodecError> {
        let remaining = self.bytes.len().saturating_sub(self.offset);
        if remaining < len {
            return Err(EtcdCodecError::Truncated {
                needed: len,
                remaining,
            });
        }
        let start = self.offset;
        self.offset += len;
        Ok(&self.bytes[start..start + len])
    }

    fn read_u8(&mut self) -> Result<u8, EtcdCodecError> {
        let raw = self.read_exact(1)?[0];
        self.last_u8 = raw;
        Ok(raw)
    }

    fn read_bool(&mut self) -> Result<bool, EtcdCodecError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            actual => Err(EtcdCodecError::InvalidBool { actual }),
        }
    }

    fn read_u32(&mut self) -> Result<u32, EtcdCodecError> {
        let raw = self.read_exact(4)?;
        Ok(u32::from_le_bytes(raw.try_into().expect("slice length checked")))
    }

    fn read_u64(&mut self) -> Result<u64, EtcdCodecError> {
        let raw = self.read_exact(8)?;
        Ok(u64::from_le_bytes(raw.try_into().expect("slice length checked")))
    }

    fn read_len(&mut self) -> Result<usize, EtcdCodecError> {
        Ok(self.read_u32()? as usize)
    }

    fn read_vec(&mut self) -> Result<Vec<u8>, EtcdCodecError> {
        let len = self.read_len()?;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_opt_vec(&mut self) -> Result<Option<Vec<u8>>, EtcdCodecError> {
        Ok(if self.read_bool()? {
            Some(self.read_vec()?)
        } else {
            None
        })
    }

    fn read_opt_u64(&mut self) -> Result<Option<u64>, EtcdCodecError> {
        Ok(if self.read_bool()? {
            Some(self.read_u64()?)
        } else {
            None
        })
    }

    fn read_opt_u32(&mut self) -> Result<Option<u32>, EtcdCodecError> {
        Ok(if self.read_bool()? {
            Some(self.read_u32()?)
        } else {
            None
        })
    }

    fn read_opt_u8(&mut self) -> Result<Option<u8>, EtcdCodecError> {
        Ok(if self.read_bool()? {
            Some(self.read_u8()?)
        } else {
            None
        })
    }

    fn read_tenant(&mut self) -> Result<TenantId, EtcdCodecError> {
        let raw = self.read_exact(32)?;
        let bytes = <[u8; 32]>::try_from(raw).expect("slice length checked");
        Ok(TenantId::from_bytes(bytes))
    }
}

fn put_tenant(out: &mut Vec<u8>, tenant: TenantId) {
    out.extend_from_slice(tenant.as_bytes());
}

fn put_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    let len = u32::try_from(len).expect("length exceeds u32::MAX");
    put_u32(out, len);
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn put_opt_bytes(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            put_bool(out, true);
            put_bytes(out, bytes);
        }
        None => put_bool(out, false),
    }
}

fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            put_bool(out, true);
            put_u64(out, value);
        }
        None => put_bool(out, false),
    }
}

fn put_opt_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            put_bool(out, true);
            put_u32(out, value);
        }
        None => put_bool(out, false),
    }
}

fn put_opt_u8(out: &mut Vec<u8>, value: Option<u8>) {
    match value {
        Some(value) => {
            put_bool(out, true);
            put_u8(out, value);
        }
        None => put_bool(out, false),
    }
}
