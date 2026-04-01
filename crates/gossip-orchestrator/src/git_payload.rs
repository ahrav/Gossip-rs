//! Typed Git shard payload carried through shard metadata.
//!
//! The coordination layer transports shard metadata as an opaque byte slice
//! (`connector_extra` in [`gossip_frontier::hint::ShardMetadata`]). This
//! module gives that byte slice a typed interpretation specific to Git
//! repo-frontier shards: one normalized repo target plus the shard-local Git
//! settings needed to reconstruct execution intent without reopening the
//! original submission request.
//!
//! # Wire format
//!
//! ```text
//! [tenant_id:32]
//! [repo_id:u64 BE]
//! [repo_key_len:u32 BE][repo_key_bytes]
//! [locator_tag:u8][locator_len:u32 BE][locator_utf8_bytes]
//! [display_name_flag:u8][display_name_len:u32 BE?][display_name_utf8_bytes?]
//! [selection_tag:u8][selection_bytes]
//! [scan_mode_tag:u8]
//! [merge_strategy_tag:u8]
//! [execution_flags:u8]
//! [debug_level_tag:u8]
//! [pack_exec_workers:u64 BE]
//! [tree_delta_cache_mb:u32 BE]
//! [engine_chunk_mb:u32 BE]
//! ```
//!
//! `selection_bytes` depends on `selection_tag`:
//!
//! - `0x00` — no extra bytes (`DefaultBranchOnly`)
//! - `0x01` — `[ref_count:u32 BE][ref_len:u32 BE][ref_bytes]...`
//! - `0x02` — `[oid_format_tag:u8][oid_bytes]`
//!
//! The format is intentionally versionless and deterministic. Equivalent
//! normalized targets must encode to identical bytes, and decode rejects
//! malformed or non-canonical inputs instead of silently normalizing them.
//!
//! # Scope boundary
//!
//! The payload carries target-local Git state only:
//!
//! - tenant-scoped repo identity (`tenant_id`, `repo_id`, `RepoKey`,
//!   `RepoLocator`)
//! - request-side selection intent
//! - repo-native scan mode / merge strategy
//! - repo-execution limits
//!
//! Run-level coordination settings such as `RunConfig`, budgets, rule paths,
//! and worker-owned runtime scratch remain outside the payload.

use std::fmt;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Component, Path};

use gossip_contracts::connector::ConnectorInputError;
use gossip_contracts::connector::ToxicDigest;
use gossip_contracts::connector::git::{
    GitDebugLevel, GitExecutionLimits, GitMergeStrategy, GitRefSelection, GitRepoTarget,
    GitScanMode, GitSelection, RepoKey, RepoKeyDecodeError, RepoLocator,
};
use gossip_contracts::coordination::shard_spec::MAX_METADATA_SIZE;
use gossip_contracts::identity::TenantId;
use scanner_git::{ObjectFormat, OidBytes, derive_repo_id};

use crate::git_request::{
    ExplicitRefValidationError, NormalizedGitRequest, NormalizedGitSelection, NormalizedGitTarget,
    validate_explicit_refs,
};

const TENANT_ID_LEN: usize = 32;
const U32_LEN: usize = std::mem::size_of::<u32>();
const U64_LEN: usize = std::mem::size_of::<u64>();
const EXECUTION_LIMITS_ENCODED_LEN: usize = 1 + 1 + U64_LEN + U32_LEN + U32_LEN;

const LOCATOR_LOCAL_PATH_TAG: u8 = 0x01;

const DISPLAY_NAME_NONE_TAG: u8 = 0x00;
const DISPLAY_NAME_SOME_TAG: u8 = 0x01;

const SELECTION_DEFAULT_BRANCH_ONLY_TAG: u8 = 0x00;
const SELECTION_EXPLICIT_REFS_TAG: u8 = 0x01;
const SELECTION_EXPLICIT_COMMIT_TAG: u8 = 0x02;

const GIT_SCAN_MODE_DIFF_HISTORY_TAG: u8 = 0x00;
const GIT_SCAN_MODE_ODB_BLOB_FAST_TAG: u8 = 0x01;

const GIT_MERGE_STRATEGY_ALL_PARENTS_TAG: u8 = 0x00;
const GIT_MERGE_STRATEGY_FIRST_PARENT_ONLY_TAG: u8 = 0x01;

const OBJECT_FORMAT_SHA1_TAG: u8 = 0x01;
const OBJECT_FORMAT_SHA256_TAG: u8 = 0x02;

const GIT_DEBUG_LEVEL_OFF_TAG: u8 = 0x00;
const GIT_DEBUG_LEVEL_STATS_TAG: u8 = 0x01;
const GIT_DEBUG_LEVEL_PERF_TAG: u8 = 0x02;

const LIMITS_FLAG_SCAN_BINARY: u8 = 1 << 0;
const LIMITS_FLAG_ENRICH_IDENTITIES: u8 = 1 << 1;
const KNOWN_LIMITS_FLAGS: u8 = LIMITS_FLAG_SCAN_BINARY | LIMITS_FLAG_ENRICH_IDENTITIES;

/// Git-specific shard payload encoded into `connector_extra`.
///
/// One payload represents exactly one normalized repo target. The payload keeps
/// the request-side selection intent intact, including the explicit-commit
/// variant that later control-plane work lowers to a synthetic ref.
#[derive(Clone, PartialEq, Eq)]
pub struct GitShardPayload {
    tenant_id: TenantId,
    repo_target: GitRepoTarget,
    repo_id: u64,
    selection: NormalizedGitSelection,
    scan_mode: GitScanMode,
    merge_strategy: GitMergeStrategy,
    execution_limits: GitExecutionLimits,
}

impl fmt::Debug for GitShardPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (locator_kind, locator_digest) = match self.repo_target.locator() {
            RepoLocator::LocalPath(path) => (
                "LocalPath",
                ToxicDigest::of_bytes(path.as_os_str().as_encoded_bytes()),
            ),
        };

        f.debug_struct("GitShardPayload")
            .field("tenant_id", &self.tenant_id)
            .field(
                "repo_key",
                &ToxicDigest::of_bytes(self.repo_target.repo_key().as_bytes()),
            )
            .field("locator_kind", &locator_kind)
            .field("locator", &locator_digest)
            .field(
                "display_name",
                &self
                    .repo_target
                    .display_name()
                    .map(|value| ToxicDigest::of_bytes(value.as_bytes())),
            )
            .field("repo_id", &self.repo_id)
            .field("selection", &self.selection)
            .field("scan_mode", &self.scan_mode)
            .field("merge_strategy", &self.merge_strategy)
            .field("execution_limits", &self.execution_limits)
            .finish()
    }
}

impl GitShardPayload {
    /// Construct a payload from explicit Git shard-local fields.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        repo_target: GitRepoTarget,
        repo_id: u64,
        selection: NormalizedGitSelection,
        scan_mode: GitScanMode,
        merge_strategy: GitMergeStrategy,
        execution_limits: GitExecutionLimits,
    ) -> Self {
        Self {
            tenant_id,
            repo_target,
            repo_id,
            selection,
            scan_mode,
            merge_strategy,
            execution_limits,
        }
    }

    /// Construct the payload for one normalized repo target.
    ///
    /// The request contributes the shared tenant scope and Git scan settings;
    /// the target contributes repo identity plus request-side selection intent.
    #[must_use]
    pub fn from_normalized_request_target(
        request: &NormalizedGitRequest,
        target: &NormalizedGitTarget,
        execution_limits: GitExecutionLimits,
    ) -> Self {
        Self::new(
            request.tenant_id(),
            target.repo_target().clone(),
            target.repo_id(),
            target.selection().clone(),
            request.scan_mode(),
            request.merge_strategy(),
            execution_limits,
        )
    }

    /// Tenant scope carried for repo-identity validation.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Canonical repo target preserved in the payload.
    #[must_use]
    pub fn repo_target(&self) -> &GitRepoTarget {
        &self.repo_target
    }

    /// Canonical repo key preserved in the payload.
    #[must_use]
    pub fn repo_key(&self) -> &RepoKey {
        self.repo_target.repo_key()
    }

    /// Canonical locator preserved in the payload.
    #[must_use]
    pub fn repo_locator(&self) -> &RepoLocator {
        self.repo_target.locator()
    }

    /// Optional diagnostic display metadata preserved in the payload.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.repo_target.display_name()
    }

    /// Stable tenant-scoped repo identifier for inner persistence namespaces.
    #[must_use]
    pub fn repo_id(&self) -> u64 {
        self.repo_id
    }

    /// Request-side selection intent preserved in the payload.
    #[must_use]
    pub fn selection(&self) -> &NormalizedGitSelection {
        &self.selection
    }

    /// Repo-native scan mode preserved in the payload.
    #[must_use]
    pub fn scan_mode(&self) -> GitScanMode {
        self.scan_mode
    }

    /// Merge-commit diff strategy preserved in the payload.
    #[must_use]
    pub fn merge_strategy(&self) -> GitMergeStrategy {
        self.merge_strategy
    }

    /// Repo-execution limits preserved in the payload.
    #[must_use]
    pub fn execution_limits(&self) -> GitExecutionLimits {
        self.execution_limits
    }

    /// Convert the payload into a contract-level [`GitSelection`] when the
    /// request-side selection is already ref-backed.
    ///
    /// Explicit-commit payloads return `None` because synthetic-ref lowering is
    /// a later control-plane step.
    #[must_use]
    pub fn git_selection(&self) -> Option<GitSelection> {
        let refs = match &self.selection {
            NormalizedGitSelection::DefaultBranchOnly => GitRefSelection::DefaultBranchOnly,
            NormalizedGitSelection::ExplicitRefs { refs } => {
                GitRefSelection::ExplicitRefs { refs: refs.clone() }
            }
            NormalizedGitSelection::ExplicitCommit { .. } => return None,
        };
        Some(GitSelection::new(refs, self.scan_mode, self.merge_strategy))
    }

    /// Return the deterministic encoded payload size in bytes.
    ///
    /// This validates the identity and selection invariants that the payload
    /// format depends on and rejects shapes that would exceed
    /// [`MAX_METADATA_SIZE`].
    pub fn encoded_len(&self) -> Result<usize, GitShardPayloadEncodeError> {
        validate_repo_identity_for_encode(self.tenant_id, &self.repo_target, self.repo_id)?;
        validate_selection_for_encode(&self.selection)?;
        validate_execution_limits_for_encode(self.execution_limits)?;

        let repo_key_len = self.repo_target.repo_key().as_bytes().len();
        let locator_len = encoded_locator_len(self.repo_target.locator())?;
        let display_name_len = encoded_display_name_len(self.repo_target.display_name());
        let selection_len = encoded_selection_len(&self.selection);

        let mut total = TENANT_ID_LEN + U64_LEN;
        total = checked_add_len(total, U32_LEN + repo_key_len)?;
        total = checked_add_len(total, locator_len)?;
        total = checked_add_len(total, display_name_len)?;
        total = checked_add_len(total, selection_len)?;
        total = checked_add_len(total, 1 + 1 + EXECUTION_LIMITS_ENCODED_LEN)?;
        enforce_metadata_limit(total)?;
        Ok(total)
    }

    /// Encode the payload into deterministic `connector_extra` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, GitShardPayloadEncodeError> {
        let encoded_len = self.encoded_len()?;
        let mut encoded = Vec::with_capacity(encoded_len);

        encoded.extend_from_slice(self.tenant_id.as_bytes());
        push_u64_be(&mut encoded, self.repo_id);
        push_len_prefixed_bytes(&mut encoded, self.repo_target.repo_key().as_bytes());
        encode_locator_into(&mut encoded, self.repo_target.locator())?;
        encode_display_name_into(&mut encoded, self.repo_target.display_name());
        encode_selection_into(&mut encoded, &self.selection);
        encoded.push(encode_scan_mode(self.scan_mode));
        encoded.push(encode_merge_strategy(self.merge_strategy));
        encode_execution_limits_into(&mut encoded, self.execution_limits);

        debug_assert_eq!(encoded.len(), encoded_len);
        Ok(encoded)
    }

    /// Decode Git payload bytes previously stored in `connector_extra`.
    ///
    /// Decode validates:
    ///
    /// - total metadata size
    /// - length-prefix truncation
    /// - enum discriminants
    /// - local-path / display-name UTF-8
    /// - explicit-ref canonical ordering
    /// - repo-key / locator agreement
    /// - tenant-scoped `repo_id` agreement
    pub fn decode(bytes: &[u8]) -> Result<Self, GitShardPayloadDecodeError> {
        if bytes.is_empty() {
            return Err(GitShardPayloadDecodeError::EmptyPayload);
        }
        if bytes.len() > MAX_METADATA_SIZE {
            return Err(GitShardPayloadDecodeError::MetadataTooLarge {
                size: bytes.len(),
                max: MAX_METADATA_SIZE,
            });
        }

        let mut cursor = DecodeCursor::new(bytes);

        let tenant_id = TenantId::from_bytes(cursor.take_array::<TENANT_ID_LEN>("tenant_id")?);
        let repo_id = cursor.take_u64("repo_id")?;

        let repo_key_bytes = cursor.take_len_prefixed_bytes("repo_key_len", "repo_key")?;
        let repo_key = RepoKey::try_from_slice(repo_key_bytes)
            .map_err(|source| GitShardPayloadDecodeError::InvalidRepoKey { source })?;
        let locator = decode_locator(&mut cursor)?;
        let display_name = decode_display_name(&mut cursor)?;
        let selection = decode_selection(&mut cursor)?;
        let scan_mode = decode_scan_mode(cursor.take_u8("scan_mode_tag")?)?;
        let merge_strategy = decode_merge_strategy(cursor.take_u8("merge_strategy_tag")?)?;
        let execution_limits = decode_execution_limits(&mut cursor)?;

        if !cursor.is_empty() {
            return Err(GitShardPayloadDecodeError::TrailingBytes {
                remaining: cursor.remaining(),
            });
        }

        let mut repo_target = GitRepoTarget::new(repo_key, locator);
        if let Some(display_name) = display_name {
            repo_target = repo_target.with_display_name(display_name);
        }
        validate_repo_identity_for_decode(tenant_id, &repo_target, repo_id)?;

        Ok(Self::new(
            tenant_id,
            repo_target,
            repo_id,
            selection,
            scan_mode,
            merge_strategy,
            execution_limits,
        ))
    }
}

/// Errors from [`GitShardPayload::encode`].
#[derive(Debug, thiserror::Error)]
pub enum GitShardPayloadEncodeError {
    /// The local-path locator was empty.
    #[error("git shard payload local-path locator requires a non-empty canonical path")]
    EmptyLocalPath,
    /// The local-path locator was not absolute.
    #[error("git shard payload local-path locator must be absolute")]
    RelativeLocalPath,
    /// The local-path locator contains directory traversal (`..`).
    #[error("git shard payload local-path locator contains directory traversal")]
    LocalPathTraversal,
    /// The local-path locator could not be represented as UTF-8.
    #[error("git shard payload local-path locator is not valid UTF-8")]
    NonUtf8LocalPath,
    /// The payload repo key does not decode as a valid local-path key.
    #[error("git shard payload repo key failed to decode: {source}")]
    RepoKeyDecode {
        /// Underlying repo-key decode failure.
        source: RepoKeyDecodeError,
    },
    /// Repo-key identity and locator identity disagree.
    #[error("git shard payload repo key and locator disagree")]
    RepoKeyLocatorMismatch,
    /// The carried repo_id does not match the tenant-scoped repo key.
    #[error("git shard payload repo_id {actual} does not match repo identity {expected}")]
    RepoIdMismatch {
        /// Repo ID recomputed from the tenant-scoped repo key.
        expected: u64,
        /// Repo ID carried in the payload.
        actual: u64,
    },
    /// Explicit-refs selection omitted refs entirely.
    #[error("git shard payload explicit refs list must be non-empty")]
    EmptyExplicitRefs,
    /// One explicit ref was empty.
    #[error("git shard payload explicit ref at position {ref_index} is empty")]
    EmptyRef {
        /// Zero-based position within the explicit-ref list.
        ref_index: usize,
    },
    /// One explicit ref contained a NUL byte.
    #[error("git shard payload explicit ref at position {ref_index} contains a NUL byte")]
    RefContainsNul {
        /// Zero-based position within the explicit-ref list.
        ref_index: usize,
    },
    /// Explicit refs were not encoded in strict sorted order.
    #[error("git shard payload explicit refs must be strictly sorted and deduplicated")]
    NonCanonicalExplicitRefs,
    /// Explicit-commit selection carried a null OID.
    #[error("git shard payload explicit commit OID must be non-null")]
    NullExplicitCommit,
    /// The `pack_exec_workers` value exceeds the portable u32 wire limit.
    #[error("git shard payload pack_exec_workers value {workers} exceeds portable u32 limit")]
    PackExecWorkersTooLarge {
        /// Worker-count override that exceeded the portable ceiling.
        workers: usize,
    },
    /// The encoded payload exceeds the shard-metadata size ceiling.
    #[error("git shard payload is too large ({size} bytes, max {max})")]
    MetadataTooLarge {
        /// Encoded payload size in bytes.
        size: usize,
        /// Metadata size ceiling in bytes.
        max: usize,
    },
}

/// Errors from [`GitShardPayload::decode`].
#[derive(Debug, thiserror::Error)]
pub enum GitShardPayloadDecodeError {
    /// No payload bytes were present.
    #[error("git shard payload is empty")]
    EmptyPayload,
    /// The input exceeds the shard-metadata size ceiling.
    #[error("git shard payload is too large ({size} bytes, max {max})")]
    MetadataTooLarge {
        /// Observed payload size in bytes.
        size: usize,
        /// Metadata size ceiling in bytes.
        max: usize,
    },
    /// The input ended before the named field could be fully decoded.
    #[error(
        "git shard payload field '{field}' is truncated (need {expected_min} bytes, got {actual})"
    )]
    Truncated {
        /// Field being decoded.
        field: &'static str,
        /// Minimum total byte count required to decode the field.
        expected_min: usize,
        /// Actual total byte count available.
        actual: usize,
    },
    /// The payload carried extra trailing bytes after a complete decode.
    #[error("git shard payload has {remaining} trailing bytes")]
    TrailingBytes {
        /// Undecoded trailing byte count.
        remaining: usize,
    },
    /// The repo key failed `ItemKey` validation.
    #[error("git shard payload repo key is invalid: {source}")]
    InvalidRepoKey {
        /// Underlying item-key validation failure.
        source: ConnectorInputError,
    },
    /// The repo key does not decode as a supported local-path key.
    #[error("git shard payload repo key failed to decode: {source}")]
    RepoKeyDecode {
        /// Underlying structured repo-key decode failure.
        source: RepoKeyDecodeError,
    },
    /// The locator kind discriminant is unknown.
    #[error("git shard payload locator tag '{0}' is unknown")]
    UnknownLocatorTag(u8),
    /// The decoded local-path locator was empty.
    #[error("git shard payload local-path locator requires a non-empty canonical path")]
    EmptyLocalPath,
    /// The decoded local-path locator was not valid UTF-8.
    #[error("git shard payload local-path locator is not valid UTF-8: {source}")]
    InvalidUtf8LocalPath {
        /// Underlying UTF-8 decode failure.
        source: std::str::Utf8Error,
    },
    /// The decoded local-path locator was not absolute.
    #[error("git shard payload local-path locator must be absolute")]
    RelativeLocalPath,
    /// The decoded local-path locator contains directory traversal (`..`).
    #[error("git shard payload local-path locator contains directory traversal")]
    LocalPathTraversal,
    /// The display-name presence flag is unknown.
    #[error("git shard payload display-name flag '{0}' is unknown")]
    UnknownDisplayNameFlag(u8),
    /// The display-name carried SOME tag with empty content (non-canonical).
    #[error("git shard payload display name uses SOME tag with empty content (non-canonical)")]
    NonCanonicalEmptyDisplayName,
    /// The display-name bytes were not valid UTF-8.
    #[error("git shard payload display name is not valid UTF-8: {source}")]
    InvalidUtf8DisplayName {
        /// Underlying UTF-8 decode failure.
        source: std::str::Utf8Error,
    },
    /// The selection discriminant is unknown.
    #[error("git shard payload selection tag '{0}' is unknown")]
    UnknownSelectionTag(u8),
    /// Explicit refs were omitted entirely.
    #[error("git shard payload explicit refs list must be non-empty")]
    EmptyExplicitRefs,
    /// One explicit ref was empty.
    #[error("git shard payload explicit ref at position {ref_index} is empty")]
    EmptyRef {
        /// Zero-based position within the explicit-ref list.
        ref_index: usize,
    },
    /// One explicit ref contained a NUL byte.
    #[error("git shard payload explicit ref at position {ref_index} contains a NUL byte")]
    RefContainsNul {
        /// Zero-based position within the explicit-ref list.
        ref_index: usize,
    },
    /// Explicit refs were not encoded in strict sorted order.
    #[error("git shard payload explicit refs must be strictly sorted and deduplicated")]
    NonCanonicalExplicitRefs,
    /// The explicit-commit object-format tag is unknown.
    #[error("git shard payload explicit commit format tag '{0}' is unknown")]
    UnknownObjectFormatTag(u8),
    /// Explicit-commit selection carried a null OID.
    #[error("git shard payload explicit commit OID must be non-null")]
    NullExplicitCommit,
    /// The scan-mode discriminant is unknown.
    #[error("git shard payload scan mode tag '{0}' is unknown")]
    UnknownScanModeTag(u8),
    /// The merge-strategy discriminant is unknown.
    #[error("git shard payload merge strategy tag '{0}' is unknown")]
    UnknownMergeStrategyTag(u8),
    /// Unknown execution-limit flags were set.
    #[error("git shard payload execution flags '{0:#04x}' are unknown")]
    UnknownExecutionFlags(u8),
    /// The debug-level discriminant is unknown.
    #[error("git shard payload debug-level tag '{0}' is unknown")]
    UnknownDebugLevelTag(u8),
    /// The encoded worker count cannot fit into `usize` on this platform.
    #[error("git shard payload pack_exec_workers value {workers} exceeds usize")]
    PackExecWorkersTooLarge {
        /// Encoded worker-count override.
        workers: u64,
    },
    /// Repo-key identity and locator identity disagree.
    #[error("git shard payload repo key and locator disagree")]
    RepoKeyLocatorMismatch,
    /// The carried repo_id does not match the tenant-scoped repo key.
    #[error("git shard payload repo_id {actual} does not match repo identity {expected}")]
    RepoIdMismatch {
        /// Repo ID recomputed from the tenant-scoped repo key.
        expected: u64,
        /// Repo ID carried in the payload.
        actual: u64,
    },
}

impl From<ExplicitRefValidationError> for GitShardPayloadEncodeError {
    fn from(err: ExplicitRefValidationError) -> Self {
        match err {
            ExplicitRefValidationError::EmptyList => Self::EmptyExplicitRefs,
            ExplicitRefValidationError::EmptyRef { ref_index } => Self::EmptyRef { ref_index },
            ExplicitRefValidationError::RefContainsNul { ref_index } => {
                Self::RefContainsNul { ref_index }
            }
            ExplicitRefValidationError::NonCanonical => Self::NonCanonicalExplicitRefs,
        }
    }
}

impl From<ExplicitRefValidationError> for GitShardPayloadDecodeError {
    fn from(err: ExplicitRefValidationError) -> Self {
        match err {
            ExplicitRefValidationError::EmptyList => Self::EmptyExplicitRefs,
            ExplicitRefValidationError::EmptyRef { ref_index } => Self::EmptyRef { ref_index },
            ExplicitRefValidationError::RefContainsNul { ref_index } => {
                Self::RefContainsNul { ref_index }
            }
            ExplicitRefValidationError::NonCanonical => Self::NonCanonicalExplicitRefs,
        }
    }
}

fn validate_repo_identity_for_encode(
    tenant_id: TenantId,
    repo_target: &GitRepoTarget,
    repo_id: u64,
) -> Result<(), GitShardPayloadEncodeError> {
    let RepoLocator::LocalPath(path) = repo_target.locator();
    validate_local_path_for_encode(path)?;

    let decoded_repo_key = repo_target
        .repo_key()
        .decode()
        .map_err(|source| GitShardPayloadEncodeError::RepoKeyDecode { source })?;
    if decoded_repo_key
        .local_path_bytes()
        .map_err(|source| GitShardPayloadEncodeError::RepoKeyDecode { source })?
        != path.as_os_str().as_encoded_bytes()
    {
        return Err(GitShardPayloadEncodeError::RepoKeyLocatorMismatch);
    }

    let expected_repo_id = derive_repo_id(tenant_id, repo_target.repo_key());
    if repo_id != expected_repo_id {
        return Err(GitShardPayloadEncodeError::RepoIdMismatch {
            expected: expected_repo_id,
            actual: repo_id,
        });
    }

    Ok(())
}

fn validate_repo_identity_for_decode(
    tenant_id: TenantId,
    repo_target: &GitRepoTarget,
    repo_id: u64,
) -> Result<(), GitShardPayloadDecodeError> {
    let RepoLocator::LocalPath(path) = repo_target.locator();
    validate_decoded_local_path(path)?;

    let decoded_repo_key = repo_target
        .repo_key()
        .decode()
        .map_err(|source| GitShardPayloadDecodeError::RepoKeyDecode { source })?;
    if decoded_repo_key
        .local_path_bytes()
        .map_err(|source| GitShardPayloadDecodeError::RepoKeyDecode { source })?
        != path.as_os_str().as_encoded_bytes()
    {
        return Err(GitShardPayloadDecodeError::RepoKeyLocatorMismatch);
    }

    let expected_repo_id = derive_repo_id(tenant_id, repo_target.repo_key());
    if repo_id != expected_repo_id {
        return Err(GitShardPayloadDecodeError::RepoIdMismatch {
            expected: expected_repo_id,
            actual: repo_id,
        });
    }

    Ok(())
}

fn validate_local_path_for_encode(path: &Path) -> Result<&str, GitShardPayloadEncodeError> {
    if path.as_os_str().is_empty() {
        return Err(GitShardPayloadEncodeError::EmptyLocalPath);
    }
    let path_str = path
        .to_str()
        .ok_or(GitShardPayloadEncodeError::NonUtf8LocalPath)?;
    if !path.is_absolute() {
        return Err(GitShardPayloadEncodeError::RelativeLocalPath);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(GitShardPayloadEncodeError::LocalPathTraversal);
    }
    Ok(path_str)
}

fn validate_decoded_local_path(path: &Path) -> Result<(), GitShardPayloadDecodeError> {
    if path.as_os_str().is_empty() {
        return Err(GitShardPayloadDecodeError::EmptyLocalPath);
    }
    if !path.is_absolute() {
        return Err(GitShardPayloadDecodeError::RelativeLocalPath);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(GitShardPayloadDecodeError::LocalPathTraversal);
    }
    Ok(())
}

fn validate_selection_for_encode(
    selection: &NormalizedGitSelection,
) -> Result<(), GitShardPayloadEncodeError> {
    match selection {
        NormalizedGitSelection::DefaultBranchOnly => Ok(()),
        NormalizedGitSelection::ExplicitRefs { refs } => {
            validate_explicit_refs(refs)?;
            Ok(())
        }
        NormalizedGitSelection::ExplicitCommit { commit } => {
            if commit.is_null() {
                return Err(GitShardPayloadEncodeError::NullExplicitCommit);
            }
            Ok(())
        }
    }
}

fn validate_execution_limits_for_encode(
    limits: GitExecutionLimits,
) -> Result<(), GitShardPayloadEncodeError> {
    if let Some(workers) = limits.pack_exec_workers()
        && workers > u32::MAX as usize
    {
        return Err(GitShardPayloadEncodeError::PackExecWorkersTooLarge { workers });
    }
    Ok(())
}

fn encoded_locator_len(locator: &RepoLocator) -> Result<usize, GitShardPayloadEncodeError> {
    match locator {
        RepoLocator::LocalPath(path) => {
            let local_path = validate_local_path_for_encode(path)?;
            checked_add_len(1, U32_LEN + local_path.len())
        }
    }
}

fn encoded_display_name_len(display_name: Option<&str>) -> usize {
    match display_name {
        Some(display_name) if !display_name.is_empty() => 1 + U32_LEN + display_name.len(),
        _ => 1,
    }
}

fn encoded_selection_len(selection: &NormalizedGitSelection) -> usize {
    match selection {
        NormalizedGitSelection::DefaultBranchOnly => 1,
        NormalizedGitSelection::ExplicitRefs { refs } => {
            1 + U32_LEN
                + refs
                    .iter()
                    .map(|value| U32_LEN + value.len())
                    .sum::<usize>()
        }
        NormalizedGitSelection::ExplicitCommit { commit } => 1 + 1 + commit.as_slice().len(),
    }
}

#[allow(clippy::manual_saturating_arithmetic)]
fn checked_add_len(current: usize, extra: usize) -> Result<usize, GitShardPayloadEncodeError> {
    // Use checked_add explicitly: on overflow, the sentinel usize::MAX is
    // guaranteed to exceed MAX_METADATA_SIZE, producing MetadataTooLarge.
    let total = current.checked_add(extra).unwrap_or(usize::MAX);
    enforce_metadata_limit(total)?;
    Ok(total)
}

fn enforce_metadata_limit(total: usize) -> Result<(), GitShardPayloadEncodeError> {
    if total > MAX_METADATA_SIZE {
        return Err(GitShardPayloadEncodeError::MetadataTooLarge {
            size: total,
            max: MAX_METADATA_SIZE,
        });
    }
    Ok(())
}

fn push_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_len_prefixed_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u32_be(
        out,
        u32::try_from(bytes.len()).expect("metadata fields always fit into u32"),
    );
    out.extend_from_slice(bytes);
}

fn encode_locator_into(
    out: &mut Vec<u8>,
    locator: &RepoLocator,
) -> Result<(), GitShardPayloadEncodeError> {
    match locator {
        RepoLocator::LocalPath(path) => {
            let local_path = validate_local_path_for_encode(path)?;
            out.push(LOCATOR_LOCAL_PATH_TAG);
            push_len_prefixed_bytes(out, local_path.as_bytes());
        }
    }
    Ok(())
}

fn encode_display_name_into(out: &mut Vec<u8>, display_name: Option<&str>) {
    match display_name {
        Some(display_name) if !display_name.is_empty() => {
            out.push(DISPLAY_NAME_SOME_TAG);
            push_len_prefixed_bytes(out, display_name.as_bytes());
        }
        _ => out.push(DISPLAY_NAME_NONE_TAG),
    }
}

fn encode_selection_into(out: &mut Vec<u8>, selection: &NormalizedGitSelection) {
    match selection {
        NormalizedGitSelection::DefaultBranchOnly => {
            out.push(SELECTION_DEFAULT_BRANCH_ONLY_TAG);
        }
        NormalizedGitSelection::ExplicitRefs { refs } => {
            out.push(SELECTION_EXPLICIT_REFS_TAG);
            push_u32_be(
                out,
                u32::try_from(refs.len()).expect("metadata fields always fit into u32"),
            );
            for value in refs {
                push_len_prefixed_bytes(out, value);
            }
        }
        NormalizedGitSelection::ExplicitCommit { commit } => {
            out.push(SELECTION_EXPLICIT_COMMIT_TAG);
            out.push(encode_object_format(commit.format()));
            out.extend_from_slice(commit.as_slice());
        }
    }
}

fn encode_scan_mode(mode: GitScanMode) -> u8 {
    match mode {
        GitScanMode::DiffHistory => GIT_SCAN_MODE_DIFF_HISTORY_TAG,
        GitScanMode::OdbBlobFast => GIT_SCAN_MODE_ODB_BLOB_FAST_TAG,
    }
}

fn encode_merge_strategy(strategy: GitMergeStrategy) -> u8 {
    match strategy {
        GitMergeStrategy::AllParents => GIT_MERGE_STRATEGY_ALL_PARENTS_TAG,
        GitMergeStrategy::FirstParentOnly => GIT_MERGE_STRATEGY_FIRST_PARENT_ONLY_TAG,
    }
}

fn encode_object_format(format: ObjectFormat) -> u8 {
    match format {
        ObjectFormat::Sha1 => OBJECT_FORMAT_SHA1_TAG,
        ObjectFormat::Sha256 => OBJECT_FORMAT_SHA256_TAG,
    }
}

fn encode_debug_level(level: GitDebugLevel) -> u8 {
    match level {
        GitDebugLevel::Off => GIT_DEBUG_LEVEL_OFF_TAG,
        GitDebugLevel::Stats => GIT_DEBUG_LEVEL_STATS_TAG,
        GitDebugLevel::Perf => GIT_DEBUG_LEVEL_PERF_TAG,
    }
}

fn encode_execution_limits_into(out: &mut Vec<u8>, limits: GitExecutionLimits) {
    let mut flags = 0u8;
    if limits.scan_binary() {
        flags |= LIMITS_FLAG_SCAN_BINARY;
    }
    if limits.enrich_identities() {
        flags |= LIMITS_FLAG_ENRICH_IDENTITIES;
    }

    out.push(flags);
    out.push(encode_debug_level(limits.debug_level()));
    push_u64_be(
        out,
        limits
            .pack_exec_workers()
            .map(|value| u64::try_from(value).expect("usize always fits into u64"))
            .unwrap_or(0),
    );
    push_u32_be(out, limits.tree_delta_cache_mb().unwrap_or(0));
    push_u32_be(out, limits.engine_chunk_mb().unwrap_or(0));
}

fn decode_locator(
    cursor: &mut DecodeCursor<'_>,
) -> Result<RepoLocator, GitShardPayloadDecodeError> {
    let tag = cursor.take_u8("locator_tag")?;
    match tag {
        LOCATOR_LOCAL_PATH_TAG => {
            let bytes = cursor.take_len_prefixed_bytes("locator_len", "locator")?;
            if bytes.is_empty() {
                return Err(GitShardPayloadDecodeError::EmptyLocalPath);
            }
            let local_path = std::str::from_utf8(bytes)
                .map_err(|source| GitShardPayloadDecodeError::InvalidUtf8LocalPath { source })?;
            let path = Path::new(local_path);
            if !path.is_absolute() {
                return Err(GitShardPayloadDecodeError::RelativeLocalPath);
            }
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(GitShardPayloadDecodeError::LocalPathTraversal);
            }
            Ok(RepoLocator::local_path(local_path))
        }
        other => Err(GitShardPayloadDecodeError::UnknownLocatorTag(other)),
    }
}

fn decode_display_name(
    cursor: &mut DecodeCursor<'_>,
) -> Result<Option<String>, GitShardPayloadDecodeError> {
    let flag = cursor.take_u8("display_name_flag")?;
    match flag {
        DISPLAY_NAME_NONE_TAG => Ok(None),
        DISPLAY_NAME_SOME_TAG => {
            let bytes = cursor.take_len_prefixed_bytes("display_name_len", "display_name")?;
            if bytes.is_empty() {
                // SOME tag with empty content is non-canonical; the encoder
                // always emits NONE_TAG for absent or empty names.
                return Err(GitShardPayloadDecodeError::NonCanonicalEmptyDisplayName);
            }
            let display_name = std::str::from_utf8(bytes)
                .map_err(|source| GitShardPayloadDecodeError::InvalidUtf8DisplayName { source })?;
            Ok(Some(display_name.to_owned()))
        }
        other => Err(GitShardPayloadDecodeError::UnknownDisplayNameFlag(other)),
    }
}

fn decode_selection(
    cursor: &mut DecodeCursor<'_>,
) -> Result<NormalizedGitSelection, GitShardPayloadDecodeError> {
    let tag = cursor.take_u8("selection_tag")?;
    match tag {
        SELECTION_DEFAULT_BRANCH_ONLY_TAG => Ok(NormalizedGitSelection::DefaultBranchOnly),
        SELECTION_EXPLICIT_REFS_TAG => {
            let count = usize::try_from(cursor.take_u32("explicit_refs_count")?)
                .expect("u32 ref counts always fit into usize");
            if count == 0 {
                return Err(GitShardPayloadDecodeError::EmptyExplicitRefs);
            }

            // Each ref needs at minimum a 4-byte length prefix plus 1 byte
            // of content, so the declared count cannot exceed the remaining
            // cursor bytes divided by that minimum. Reject early to avoid an
            // unbounded `Vec::with_capacity` allocation from a crafted count.
            const MIN_BYTES_PER_REF: usize = U32_LEN + 1;
            let capacity = count.min(cursor.remaining() / MIN_BYTES_PER_REF);
            if capacity < count {
                return Err(GitShardPayloadDecodeError::Truncated {
                    field: "explicit_refs",
                    expected_min: count.saturating_mul(MIN_BYTES_PER_REF),
                    actual: cursor.remaining(),
                });
            }

            let mut refs: Vec<Vec<u8>> = Vec::with_capacity(capacity);
            for ref_index in 0..count {
                let value = cursor.take_len_prefixed_bytes("explicit_ref_len", "explicit_ref")?;
                if value.is_empty() {
                    return Err(GitShardPayloadDecodeError::EmptyRef { ref_index });
                }
                if value.contains(&0) {
                    return Err(GitShardPayloadDecodeError::RefContainsNul { ref_index });
                }
                if let Some(prev) = refs.last()
                    && prev.as_slice() >= value
                {
                    return Err(GitShardPayloadDecodeError::NonCanonicalExplicitRefs);
                }
                refs.push(value.to_vec());
            }

            Ok(NormalizedGitSelection::ExplicitRefs { refs })
        }
        SELECTION_EXPLICIT_COMMIT_TAG => {
            let format = decode_object_format(cursor.take_u8("explicit_commit_format")?)?;
            let commit_bytes = cursor.take("explicit_commit", format.oid_len() as usize)?;
            let commit = OidBytes::try_from_slice(commit_bytes)
                .expect("object-format length determines the OID width");
            if commit.is_null() {
                return Err(GitShardPayloadDecodeError::NullExplicitCommit);
            }
            Ok(NormalizedGitSelection::ExplicitCommit { commit })
        }
        other => Err(GitShardPayloadDecodeError::UnknownSelectionTag(other)),
    }
}

fn decode_object_format(tag: u8) -> Result<ObjectFormat, GitShardPayloadDecodeError> {
    match tag {
        OBJECT_FORMAT_SHA1_TAG => Ok(ObjectFormat::Sha1),
        OBJECT_FORMAT_SHA256_TAG => Ok(ObjectFormat::Sha256),
        other => Err(GitShardPayloadDecodeError::UnknownObjectFormatTag(other)),
    }
}

fn decode_scan_mode(tag: u8) -> Result<GitScanMode, GitShardPayloadDecodeError> {
    match tag {
        GIT_SCAN_MODE_DIFF_HISTORY_TAG => Ok(GitScanMode::DiffHistory),
        GIT_SCAN_MODE_ODB_BLOB_FAST_TAG => Ok(GitScanMode::OdbBlobFast),
        other => Err(GitShardPayloadDecodeError::UnknownScanModeTag(other)),
    }
}

fn decode_merge_strategy(tag: u8) -> Result<GitMergeStrategy, GitShardPayloadDecodeError> {
    match tag {
        GIT_MERGE_STRATEGY_ALL_PARENTS_TAG => Ok(GitMergeStrategy::AllParents),
        GIT_MERGE_STRATEGY_FIRST_PARENT_ONLY_TAG => Ok(GitMergeStrategy::FirstParentOnly),
        other => Err(GitShardPayloadDecodeError::UnknownMergeStrategyTag(other)),
    }
}

fn decode_debug_level(tag: u8) -> Result<GitDebugLevel, GitShardPayloadDecodeError> {
    match tag {
        GIT_DEBUG_LEVEL_OFF_TAG => Ok(GitDebugLevel::Off),
        GIT_DEBUG_LEVEL_STATS_TAG => Ok(GitDebugLevel::Stats),
        GIT_DEBUG_LEVEL_PERF_TAG => Ok(GitDebugLevel::Perf),
        other => Err(GitShardPayloadDecodeError::UnknownDebugLevelTag(other)),
    }
}

fn decode_execution_limits(
    cursor: &mut DecodeCursor<'_>,
) -> Result<GitExecutionLimits, GitShardPayloadDecodeError> {
    let flags = cursor.take_u8("execution_flags")?;
    if flags & !KNOWN_LIMITS_FLAGS != 0 {
        return Err(GitShardPayloadDecodeError::UnknownExecutionFlags(flags));
    }

    let debug_level = decode_debug_level(cursor.take_u8("debug_level_tag")?)?;
    let pack_exec_workers = cursor.take_u64("pack_exec_workers")?;
    let tree_delta_cache_mb = cursor.take_u32("tree_delta_cache_mb")?;
    let engine_chunk_mb = cursor.take_u32("engine_chunk_mb")?;

    let mut limits = GitExecutionLimits::default()
        .with_scan_binary(flags & LIMITS_FLAG_SCAN_BINARY != 0)
        .with_enrich_identities(flags & LIMITS_FLAG_ENRICH_IDENTITIES != 0)
        .with_debug_level(debug_level);

    if pack_exec_workers != 0 {
        // Enforce the same u32 ceiling as encode to reject wire values that
        // no encoder will produce.
        if pack_exec_workers > u64::from(u32::MAX) {
            return Err(GitShardPayloadDecodeError::PackExecWorkersTooLarge {
                workers: pack_exec_workers,
            });
        }
        let workers = usize::try_from(pack_exec_workers).map_err(|_| {
            GitShardPayloadDecodeError::PackExecWorkersTooLarge {
                workers: pack_exec_workers,
            }
        })?;
        limits = limits.with_pack_exec_workers(
            NonZeroUsize::new(workers)
                .expect("zero workers were filtered before NonZero conversion"),
        );
    }
    if let Some(tree_delta_cache_mb) = NonZeroU32::new(tree_delta_cache_mb) {
        limits = limits.with_tree_delta_cache_mb(tree_delta_cache_mb);
    }
    if let Some(engine_chunk_mb) = NonZeroU32::new(engine_chunk_mb) {
        limits = limits.with_engine_chunk_mb(engine_chunk_mb);
    }

    Ok(limits)
}

struct DecodeCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DecodeCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(
        &mut self,
        field: &'static str,
        len: usize,
    ) -> Result<&'a [u8], GitShardPayloadDecodeError> {
        let expected_min = self.offset.saturating_add(len);
        if expected_min > self.bytes.len() {
            return Err(GitShardPayloadDecodeError::Truncated {
                field,
                expected_min,
                actual: self.bytes.len(),
            });
        }

        let start = self.offset;
        self.offset = expected_min;
        Ok(&self.bytes[start..expected_min])
    }

    fn take_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], GitShardPayloadDecodeError> {
        Ok(self
            .take(field, N)?
            .try_into()
            .expect("fixed-width decode uses exact lengths"))
    }

    fn take_u8(&mut self, field: &'static str) -> Result<u8, GitShardPayloadDecodeError> {
        Ok(self.take(field, 1)?[0])
    }

    fn take_u32(&mut self, field: &'static str) -> Result<u32, GitShardPayloadDecodeError> {
        Ok(u32::from_be_bytes(self.take_array::<U32_LEN>(field)?))
    }

    fn take_u64(&mut self, field: &'static str) -> Result<u64, GitShardPayloadDecodeError> {
        Ok(u64::from_be_bytes(self.take_array::<U64_LEN>(field)?))
    }

    fn take_len_prefixed_bytes(
        &mut self,
        len_field: &'static str,
        data_field: &'static str,
    ) -> Result<&'a [u8], GitShardPayloadDecodeError> {
        let len =
            usize::try_from(self.take_u32(len_field)?).expect("u32 lengths always fit into usize");
        self.take(data_field, len)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::num::{NonZeroU32, NonZeroUsize};
    use std::path::{Path, PathBuf};

    use gossip_frontier::hint::{ShardSpecScratch, decode_connector_extra, range_shard_ref};
    use tempfile::tempdir;

    use super::*;
    use crate::git_request::{GitRequest, GitRequestSelection, GitRequestTarget};
    use crate::test_support::{init_git_repo, run_config};

    fn tenant(byte: u8) -> TenantId {
        TenantId::from_bytes([byte; 32])
    }

    fn default_scan_mode() -> GitScanMode {
        GitScanMode::OdbBlobFast
    }

    fn default_merge_strategy() -> GitMergeStrategy {
        GitMergeStrategy::AllParents
    }

    fn init_repo(dir: &Path) {
        init_git_repo(dir, "git-payload-tests@example.com", "Git Payload Tests");
    }

    fn execution_limits() -> GitExecutionLimits {
        GitExecutionLimits::default()
            .with_pack_exec_workers(NonZeroUsize::new(7).expect("non-zero workers"))
            .with_scan_binary(true)
            .with_enrich_identities(true)
            .with_debug_level(GitDebugLevel::Perf)
            .with_tree_delta_cache_mb(NonZeroU32::new(128).expect("non-zero cache"))
            .with_engine_chunk_mb(NonZeroU32::new(64).expect("non-zero chunk"))
    }

    fn payload_from_request(
        request: GitRequest,
        limits: GitExecutionLimits,
    ) -> (NormalizedGitRequest, GitShardPayload) {
        let normalized = request.normalize().expect("normalize request");
        let payload = GitShardPayload::from_normalized_request_target(
            &normalized,
            &normalized.targets()[0],
            limits,
        );
        (normalized, payload)
    }

    fn repo_key_len(payload: &GitShardPayload) -> usize {
        payload.repo_key().as_bytes().len()
    }

    fn locator_tag_offset(payload: &GitShardPayload) -> usize {
        TENANT_ID_LEN + U64_LEN + U32_LEN + repo_key_len(payload)
    }

    fn locator_path_len(payload: &GitShardPayload) -> usize {
        payload
            .repo_locator()
            .as_local_path()
            .expect("local path")
            .to_str()
            .expect("UTF-8 path")
            .len()
    }

    fn display_name_flag_offset(payload: &GitShardPayload) -> usize {
        // locator_tag (1) + locator_len (4) + locator_bytes
        locator_tag_offset(payload) + 1 + U32_LEN + locator_path_len(payload)
    }

    fn selection_tag_offset(payload: &GitShardPayload) -> usize {
        let base = display_name_flag_offset(payload) + 1; // flag byte
        match payload.display_name() {
            Some(name) => base + U32_LEN + name.len(),
            None => base,
        }
    }

    fn scan_mode_tag_offset(payload: &GitShardPayload) -> usize {
        selection_tag_offset(payload) + encoded_selection_len(payload.selection())
    }

    fn merge_strategy_tag_offset(payload: &GitShardPayload) -> usize {
        scan_mode_tag_offset(payload) + 1
    }

    fn execution_flags_offset(payload: &GitShardPayload) -> usize {
        merge_strategy_tag_offset(payload) + 1
    }

    fn debug_level_tag_offset(payload: &GitShardPayload) -> usize {
        execution_flags_offset(payload) + 1
    }

    fn encode_unchecked_from_payload(
        payload: &GitShardPayload,
        repo_id: u64,
        selection: &NormalizedGitSelection,
        display_name: Option<&str>,
    ) -> Vec<u8> {
        let locator_path = payload
            .repo_locator()
            .as_local_path()
            .expect("local path")
            .to_str()
            .expect("UTF-8 path");
        let mut encoded = Vec::new();
        encoded.extend_from_slice(payload.tenant_id().as_bytes());
        push_u64_be(&mut encoded, repo_id);
        push_len_prefixed_bytes(&mut encoded, payload.repo_key().as_bytes());
        encoded.push(LOCATOR_LOCAL_PATH_TAG);
        push_len_prefixed_bytes(&mut encoded, locator_path.as_bytes());
        encode_display_name_into(&mut encoded, display_name);
        encode_selection_into(&mut encoded, selection);
        encoded.push(encode_scan_mode(payload.scan_mode()));
        encoded.push(encode_merge_strategy(payload.merge_strategy()));
        encode_execution_limits_into(&mut encoded, payload.execution_limits());
        encoded
    }

    #[test]
    fn payload_round_trips_one_default_branch_target() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let (normalized, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0x11),
                dir.path(),
                run_config(),
                GitScanMode::DiffHistory,
                GitMergeStrategy::FirstParentOnly,
            ),
            execution_limits(),
        );

        let encoded = payload.encode().expect("encode payload");
        let decoded = GitShardPayload::decode(&encoded).expect("decode payload");

        assert_eq!(decoded, payload);
        assert_eq!(
            decoded.git_selection(),
            Some(GitSelection::new(
                GitRefSelection::DefaultBranchOnly,
                GitScanMode::DiffHistory,
                GitMergeStrategy::FirstParentOnly,
            ))
        );
        assert_eq!(decoded.execution_limits(), execution_limits());
        assert_eq!(decoded.repo_target(), normalized.targets()[0].repo_target());
    }

    #[test]
    fn payload_encode_is_deterministic_for_equivalent_explicit_ref_requests() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let refs_a = [
            b"refs/heads/b".as_slice(),
            b"refs/heads/a".as_slice(),
            b"refs/heads/a".as_slice(),
        ];
        let refs_b = [b"refs/heads/a".as_slice(), b"refs/heads/b".as_slice()];

        let (_, payload_a) = payload_from_request(
            GitRequest::repo_with_explicit_refs(
                tenant(0x22),
                dir.path(),
                refs_a,
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let (_, payload_b) = payload_from_request(
            GitRequest::repo_with_explicit_refs(
                tenant(0x22),
                dir.path(),
                refs_b,
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );

        assert_eq!(
            payload_a.encode().expect("encode payload a"),
            payload_b.encode().expect("encode payload b")
        );
    }

    #[test]
    fn explicit_commit_round_trips_without_lowering_to_git_selection() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let commit_hex = b"0123456789abcdef0123456789abcdef01234567";

        let (_, payload) = payload_from_request(
            GitRequest::repo_with_explicit_commit(
                tenant(0x33),
                dir.path(),
                commit_hex.as_slice(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );

        let decoded = GitShardPayload::decode(&payload.encode().expect("encode payload"))
            .expect("decode payload");

        assert_eq!(decoded, payload);
        assert!(decoded.git_selection().is_none());
        assert!(matches!(
            decoded.selection(),
            NormalizedGitSelection::ExplicitCommit { .. }
        ));
    }

    #[test]
    fn payload_round_trips_through_metadata_envelope() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0x44),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let encoded = payload.encode().expect("encode payload");

        let mut scratch = ShardSpecScratch::new();
        let spec = range_shard_ref(b"a", b"z", &encoded, &mut scratch).expect("range shard ref");
        let connector_extra = decode_connector_extra(spec).expect("decode connector extra");
        let decoded = GitShardPayload::decode(connector_extra).expect("decode payload");

        assert_eq!(decoded, payload);
    }

    #[test]
    fn encode_rejects_payloads_that_exceed_metadata_capacity() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let normalized = GitRequest::single_repo(
            tenant(0x55),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize request");
        let target = normalized.targets()[0]
            .repo_target()
            .clone()
            .with_display_name("x".repeat(MAX_METADATA_SIZE));
        let payload = GitShardPayload::new(
            normalized.tenant_id(),
            target,
            normalized.targets()[0].repo_id(),
            normalized.targets()[0].selection().clone(),
            normalized.scan_mode(),
            normalized.merge_strategy(),
            GitExecutionLimits::default(),
        );

        let err = payload.encode().expect_err("oversized payload must fail");
        assert!(matches!(
            err,
            GitShardPayloadEncodeError::MetadataTooLarge { .. }
        ));
    }

    #[test]
    fn encode_rejects_non_canonical_explicit_refs() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let normalized = GitRequest::single_repo(
            tenant(0x66),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize request");
        let payload = GitShardPayload::new(
            normalized.tenant_id(),
            normalized.targets()[0].repo_target().clone(),
            normalized.targets()[0].repo_id(),
            NormalizedGitSelection::ExplicitRefs {
                refs: vec![b"refs/heads/b".to_vec(), b"refs/heads/a".to_vec()],
            },
            normalized.scan_mode(),
            normalized.merge_strategy(),
            GitExecutionLimits::default(),
        );

        let err = payload
            .encode()
            .expect_err("non-canonical explicit refs must fail");
        assert!(matches!(
            err,
            GitShardPayloadEncodeError::NonCanonicalExplicitRefs
        ));
    }

    #[test]
    fn decode_rejects_empty_payload() {
        let err = GitShardPayload::decode(&[]).expect_err("empty payload must fail");
        assert!(matches!(err, GitShardPayloadDecodeError::EmptyPayload));
    }

    #[test]
    fn decode_rejects_unknown_locator_tag() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0x77),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        encoded[locator_tag_offset(&payload)] = 0x7F;

        let err = GitShardPayload::decode(&encoded).expect_err("unknown locator tag must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownLocatorTag(0x7F)
        ));
    }

    #[test]
    fn decode_rejects_truncated_payload() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0x78),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            execution_limits(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        encoded.pop();

        let err = GitShardPayload::decode(&encoded).expect_err("truncated payload must fail");
        assert!(matches!(err, GitShardPayloadDecodeError::Truncated { .. }));
    }

    #[test]
    fn decode_rejects_non_canonical_explicit_refs() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let normalized = GitRequest::new(
            tenant(0x79),
            vec![GitRequestTarget::new(
                dir.path(),
                GitRequestSelection::DefaultBranchOnly,
            )],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize request");

        let payload = GitShardPayload::from_normalized_request_target(
            &normalized,
            &normalized.targets()[0],
            GitExecutionLimits::default(),
        );
        let encoded = encode_unchecked_from_payload(
            &payload,
            normalized.targets()[0].repo_id(),
            &NormalizedGitSelection::ExplicitRefs {
                refs: vec![b"refs/heads/b".to_vec(), b"refs/heads/a".to_vec()],
            },
            Some("secret-display"),
        );

        let err =
            GitShardPayload::decode(&encoded).expect_err("decode must reject non-canonical refs");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::NonCanonicalExplicitRefs
        ));
    }

    #[test]
    fn decode_rejects_repo_id_mismatch() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0x7A),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );

        let encoded = encode_unchecked_from_payload(
            &payload,
            payload.repo_id() + 1,
            payload.selection(),
            payload.display_name(),
        );

        let err = GitShardPayload::decode(&encoded).expect_err("repo_id mismatch must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::RepoIdMismatch { .. }
        ));
    }

    #[test]
    fn debug_redacts_repo_path_display_name_and_refs() {
        let dir = tempdir().expect("tempdir");
        let repo = dir.path().join("super-secret-repo");
        fs::create_dir(&repo).expect("create repo");
        init_repo(&repo);

        let request = GitRequest::new(
            tenant(0x7B),
            vec![
                GitRequestTarget::new(
                    &repo,
                    GitRequestSelection::explicit_refs([
                        b"refs/heads/private".as_slice(),
                        b"refs/tags/confidential".as_slice(),
                    ]),
                )
                .with_display_name("top-secret/repo"),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );
        let (_, payload) = payload_from_request(request, GitExecutionLimits::default());
        let rendered = format!("{payload:?}");

        assert!(
            !rendered.contains("super-secret-repo"),
            "Debug output must not leak the raw repo path: {rendered}"
        );
        assert!(
            !rendered.contains("top-secret/repo"),
            "Debug output must not leak the display name: {rendered}"
        );
        assert!(
            !rendered.contains("refs/heads/private"),
            "Debug output must not leak explicit refs: {rendered}"
        );
    }

    #[test]
    fn debug_redacts_explicit_commit_oid() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let commit_hex = b"0123456789abcdef0123456789abcdef01234567";
        let (_, payload) = payload_from_request(
            GitRequest::repo_with_explicit_commit(
                tenant(0x7C),
                dir.path(),
                commit_hex.as_slice(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let rendered = format!("{payload:?}");

        assert!(
            !rendered.contains("0123456789abcdef0123456789abcdef01234567"),
            "Debug output must not leak explicit commit bytes: {rendered}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn encode_rejects_non_utf8_local_path() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let non_utf8_path = PathBuf::from(OsString::from_vec(vec![b'/', b'r', 0x80, b'o']));
        let repo_key = RepoKey::for_local_path(non_utf8_path.as_os_str().as_encoded_bytes())
            .expect("repo key");
        let payload = GitShardPayload::new(
            tenant(0x7D),
            GitRepoTarget::new(repo_key.clone(), RepoLocator::local_path(non_utf8_path)),
            derive_repo_id(tenant(0x7D), &repo_key),
            NormalizedGitSelection::DefaultBranchOnly,
            default_scan_mode(),
            default_merge_strategy(),
            GitExecutionLimits::default(),
        );

        let err = payload
            .encode()
            .expect_err("non-UTF-8 local path must be rejected");
        assert!(matches!(err, GitShardPayloadEncodeError::NonUtf8LocalPath));
    }

    /// Build a raw payload with an arbitrary locator path (bypasses encode
    /// validation). Uses the given `locator_bytes` directly in the wire
    /// format, with a matching `RepoKey` derived from `canonical_path`.
    fn encode_raw_with_locator(
        tenant_id: TenantId,
        canonical_path: &Path,
        locator_bytes: &[u8],
    ) -> Vec<u8> {
        let repo_key = RepoKey::for_local_path(canonical_path.as_os_str().as_encoded_bytes())
            .expect("repo key");
        let repo_id = derive_repo_id(tenant_id, &repo_key);
        let mut out = Vec::new();
        out.extend_from_slice(tenant_id.as_bytes());
        push_u64_be(&mut out, repo_id);
        push_len_prefixed_bytes(&mut out, repo_key.as_bytes());
        out.push(LOCATOR_LOCAL_PATH_TAG);
        push_len_prefixed_bytes(&mut out, locator_bytes);
        out.push(DISPLAY_NAME_NONE_TAG);
        out.push(SELECTION_DEFAULT_BRANCH_ONLY_TAG);
        out.push(GIT_SCAN_MODE_ODB_BLOB_FAST_TAG);
        out.push(GIT_MERGE_STRATEGY_ALL_PARENTS_TAG);
        encode_execution_limits_into(&mut out, GitExecutionLimits::default());
        out
    }

    // ── Decode rejection tests ──────────────────────────────────────────

    #[test]
    fn decode_rejects_trailing_bytes() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xD0),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        encoded.push(0x42);

        let err = GitShardPayload::decode(&encoded).expect_err("trailing bytes must fail");
        assert!(
            matches!(
                err,
                GitShardPayloadDecodeError::TrailingBytes { remaining: 1 }
            ),
            "expected TrailingBytes {{ remaining: 1 }}, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_oversized_payload() {
        let oversized = vec![0u8; MAX_METADATA_SIZE + 1];
        let err = GitShardPayload::decode(&oversized).expect_err("oversized payload must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::MetadataTooLarge {
                size,
                max,
            } if size == MAX_METADATA_SIZE + 1 && max == MAX_METADATA_SIZE
        ));
    }

    #[test]
    fn decode_rejects_unknown_selection_tag() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xD1),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        let offset = selection_tag_offset(&payload);
        encoded[offset] = 0xFF;

        let err = GitShardPayload::decode(&encoded).expect_err("unknown selection tag must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownSelectionTag(0xFF)
        ));
    }

    #[test]
    fn decode_rejects_unknown_scan_mode_tag() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xD2),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        let offset = scan_mode_tag_offset(&payload);
        encoded[offset] = 0xFF;

        let err = GitShardPayload::decode(&encoded).expect_err("unknown scan mode tag must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownScanModeTag(0xFF)
        ));
    }

    #[test]
    fn decode_rejects_unknown_merge_strategy_tag() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xD3),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        let offset = merge_strategy_tag_offset(&payload);
        encoded[offset] = 0xFF;

        let err =
            GitShardPayload::decode(&encoded).expect_err("unknown merge strategy tag must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownMergeStrategyTag(0xFF)
        ));
    }

    #[test]
    fn decode_rejects_unknown_execution_flags() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xD4),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        let offset = execution_flags_offset(&payload);
        encoded[offset] = 0xFF;

        let err = GitShardPayload::decode(&encoded).expect_err("unknown execution flags must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownExecutionFlags(0xFF)
        ));
    }

    #[test]
    fn decode_rejects_unknown_debug_level_tag() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xD5),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        let offset = debug_level_tag_offset(&payload);
        encoded[offset] = 0xFF;

        let err = GitShardPayload::decode(&encoded).expect_err("unknown debug level tag must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownDebugLevelTag(0xFF)
        ));
    }

    #[test]
    fn decode_rejects_unknown_display_name_flag() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xD6),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        let offset = display_name_flag_offset(&payload);
        encoded[offset] = 0xFF;

        let err =
            GitShardPayload::decode(&encoded).expect_err("unknown display name flag must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownDisplayNameFlag(0xFF)
        ));
    }

    #[test]
    fn decode_rejects_unknown_object_format_tag() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let commit_hex = b"0123456789abcdef0123456789abcdef01234567";
        let (_, payload) = payload_from_request(
            GitRequest::repo_with_explicit_commit(
                tenant(0xD7),
                dir.path(),
                commit_hex.as_slice(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        // Object format tag is at selection_tag + 1 (after the 0x02 commit tag).
        let offset = selection_tag_offset(&payload) + 1;
        encoded[offset] = 0xFF;

        let err =
            GitShardPayload::decode(&encoded).expect_err("unknown object format tag must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::UnknownObjectFormatTag(0xFF)
        ));
    }

    #[test]
    fn decode_rejects_empty_locator_path() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let canonical = fs::canonicalize(dir.path()).expect("canonical path");
        let encoded = encode_raw_with_locator(tenant(0xD8), &canonical, b"");

        let err = GitShardPayload::decode(&encoded).expect_err("empty locator path must fail");
        assert!(matches!(err, GitShardPayloadDecodeError::EmptyLocalPath));
    }

    #[test]
    fn decode_rejects_relative_locator_path() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let canonical = fs::canonicalize(dir.path()).expect("canonical path");
        let encoded = encode_raw_with_locator(tenant(0xD9), &canonical, b"relative/path");

        let err = GitShardPayload::decode(&encoded).expect_err("relative locator path must fail");
        assert!(matches!(err, GitShardPayloadDecodeError::RelativeLocalPath));
    }

    #[test]
    fn decode_rejects_non_utf8_locator() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let canonical = fs::canonicalize(dir.path()).expect("canonical path");
        let encoded = encode_raw_with_locator(tenant(0xDA), &canonical, &[b'/', 0xFF, 0xFE]);

        let err = GitShardPayload::decode(&encoded).expect_err("non-UTF-8 locator must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::InvalidUtf8LocalPath { .. }
        ));
    }

    #[test]
    fn decode_rejects_path_traversal_in_locator() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let canonical = fs::canonicalize(dir.path()).expect("canonical path");
        let encoded =
            encode_raw_with_locator(tenant(0xDB), &canonical, b"/tmp/repo/../../etc/passwd");

        let err = GitShardPayload::decode(&encoded).expect_err("path traversal must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::LocalPathTraversal
        ));
    }

    #[test]
    fn decode_rejects_non_utf8_display_name() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xDC),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        // Build a raw payload with an invalid UTF-8 display name by
        // replacing the NONE flag with SOME + bad bytes.
        let encoded = payload.encode().expect("encode payload");
        let flag_offset = display_name_flag_offset(&payload);

        // Rebuild: everything before the display-name flag, then inject
        // a SOME flag with invalid UTF-8 bytes, then the rest.
        let mut patched = encoded[..flag_offset].to_vec();
        patched.push(DISPLAY_NAME_SOME_TAG);
        push_u32_be(&mut patched, 2);
        patched.extend_from_slice(&[0xFF, 0xFE]);
        patched.extend_from_slice(&encoded[flag_offset + 1..]);

        let err = GitShardPayload::decode(&patched).expect_err("non-UTF-8 display name must fail");
        assert!(matches!(
            err,
            GitShardPayloadDecodeError::InvalidUtf8DisplayName { .. }
        ));
    }

    #[test]
    fn decode_rejects_empty_explicit_refs_on_decode() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xDD),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let encoded = payload.encode().expect("encode payload");
        let sel_offset = selection_tag_offset(&payload);

        // Replace selection with explicit-refs tag + count=0.
        let mut patched = encoded[..sel_offset].to_vec();
        patched.push(SELECTION_EXPLICIT_REFS_TAG);
        push_u32_be(&mut patched, 0);
        // Append the remaining fields after the original 1-byte selection.
        patched.extend_from_slice(&encoded[sel_offset + 1..]);

        let err =
            GitShardPayload::decode(&patched).expect_err("empty explicit refs on decode must fail");
        assert!(matches!(err, GitShardPayloadDecodeError::EmptyExplicitRefs));
    }

    #[test]
    fn decode_rejects_inflated_ref_count() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xDE),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let encoded = payload.encode().expect("encode payload");
        let sel_offset = selection_tag_offset(&payload);

        // Replace selection with explicit-refs tag + count=0xFFFFFFFF.
        let mut patched = encoded[..sel_offset].to_vec();
        patched.push(SELECTION_EXPLICIT_REFS_TAG);
        push_u32_be(&mut patched, 0xFFFF_FFFF);
        // Append remaining fields so the payload is otherwise well-formed.
        patched.extend_from_slice(&encoded[sel_offset + 1..]);

        let err = GitShardPayload::decode(&patched)
            .expect_err("inflated ref count must be rejected before allocation");
        assert!(
            matches!(err, GitShardPayloadDecodeError::Truncated { .. }),
            "expected Truncated from bounds check, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_null_explicit_commit() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        // Build a valid explicit-commit payload, then zero out the OID bytes.
        let commit_hex = b"0123456789abcdef0123456789abcdef01234567";
        let (_, payload) = payload_from_request(
            GitRequest::repo_with_explicit_commit(
                tenant(0xDF),
                dir.path(),
                commit_hex.as_slice(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");
        // OID bytes start after selection_tag (1) + object_format_tag (1).
        let oid_start = selection_tag_offset(&payload) + 2;
        let oid_len = OidBytes::SHA1_LEN as usize;
        for byte in &mut encoded[oid_start..oid_start + oid_len] {
            *byte = 0;
        }

        let err =
            GitShardPayload::decode(&encoded).expect_err("null explicit commit must be rejected");
        assert!(
            matches!(err, GitShardPayloadDecodeError::NullExplicitCommit),
            "expected NullExplicitCommit, got {err:?}"
        );
    }

    // ── Round-trip tests ───────────────────────────────────────────────

    #[test]
    fn payload_round_trips_explicit_refs_selection() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let refs = [
            b"refs/heads/beta".as_slice(),
            b"refs/heads/alpha".as_slice(),
            b"refs/tags/v1.0".as_slice(),
        ];
        let (_, payload) = payload_from_request(
            GitRequest::repo_with_explicit_refs(
                tenant(0xE0),
                dir.path(),
                refs,
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );

        let encoded = payload.encode().expect("encode payload");
        let decoded = GitShardPayload::decode(&encoded).expect("decode payload");

        assert_eq!(decoded, payload);
        let selection = decoded
            .git_selection()
            .expect("explicit-refs selection must lower to GitSelection");
        match selection.refs() {
            GitRefSelection::ExplicitRefs { refs } => {
                // Normalization sorts and deduplicates.
                assert_eq!(refs.len(), 3);
                assert!(refs[0] < refs[1], "refs must be in canonical sorted order");
                assert!(refs[1] < refs[2], "refs must be in canonical sorted order");
            }
            other => panic!("expected ExplicitRefs, got {other:?}"),
        }
    }

    #[test]
    fn payload_round_trips_with_display_name() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xE1),
            vec![
                GitRequestTarget::new(dir.path(), GitRequestSelection::DefaultBranchOnly)
                    .with_display_name("test-display"),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );
        let (_, payload) = payload_from_request(request, GitExecutionLimits::default());

        let encoded = payload.encode().expect("encode payload");
        let decoded = GitShardPayload::decode(&encoded).expect("decode payload");

        assert_eq!(decoded, payload);
        assert_eq!(decoded.display_name(), Some("test-display"));
    }

    #[test]
    fn payload_round_trips_without_display_name() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xE2),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );

        let encoded = payload.encode().expect("encode payload");
        let decoded = GitShardPayload::decode(&encoded).expect("decode payload");

        assert_eq!(decoded, payload);
        assert_eq!(decoded.display_name(), None);
    }

    #[test]
    fn payload_round_trips_default_execution_limits() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xE3),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );

        let encoded = payload.encode().expect("encode payload");
        let decoded = GitShardPayload::decode(&encoded).expect("decode payload");

        let limits = decoded.execution_limits();
        assert_eq!(limits.pack_exec_workers(), None);
        assert_eq!(limits.tree_delta_cache_mb(), None);
        assert_eq!(limits.engine_chunk_mb(), None);
        assert!(!limits.scan_binary());
        assert!(!limits.enrich_identities());
        assert_eq!(limits.debug_level(), GitDebugLevel::Off);
    }

    #[test]
    fn encode_rejects_path_with_traversal_component() {
        let repo_key =
            RepoKey::for_local_path(b"/repo/../etc/passwd").expect("repo key from raw bytes");
        let locator = RepoLocator::local_path("/repo/../etc/passwd");
        let payload = GitShardPayload::new(
            tenant(0xF0),
            GitRepoTarget::new(repo_key.clone(), locator),
            derive_repo_id(tenant(0xF0), &repo_key),
            NormalizedGitSelection::DefaultBranchOnly,
            default_scan_mode(),
            default_merge_strategy(),
            GitExecutionLimits::default(),
        );

        let err = payload
            .encode()
            .expect_err("path with traversal must be rejected on encode");
        assert!(
            matches!(err, GitShardPayloadEncodeError::LocalPathTraversal),
            "expected LocalPathTraversal, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_non_canonical_display_name_some_tag_with_empty_content() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xF1),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let encoded = payload.encode().expect("encode payload");
        let flag_offset = display_name_flag_offset(&payload);

        // Inject SOME tag + 0-length content (non-canonical).
        let mut patched = encoded[..flag_offset].to_vec();
        patched.push(DISPLAY_NAME_SOME_TAG);
        push_u32_be(&mut patched, 0);
        patched.extend_from_slice(&encoded[flag_offset + 1..]);

        let err = GitShardPayload::decode(&patched)
            .expect_err("SOME tag with empty content must be rejected as non-canonical");
        assert!(
            matches!(
                err,
                GitShardPayloadDecodeError::NonCanonicalEmptyDisplayName
            ),
            "expected NonCanonicalEmptyDisplayName, got {err:?}"
        );
    }

    #[test]
    fn decode_rejects_pack_exec_workers_above_u32_max() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let (_, payload) = payload_from_request(
            GitRequest::single_repo(
                tenant(0xF2),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            ),
            GitExecutionLimits::default(),
        );
        let mut encoded = payload.encode().expect("encode payload");

        // pack_exec_workers is at debug_level_tag_offset + 1 (after the 1-byte
        // debug level tag), encoded as u64 BE.
        let workers_offset = debug_level_tag_offset(&payload) + 1;
        let over_u32_max: u64 = u64::from(u32::MAX) + 1;
        encoded[workers_offset..workers_offset + U64_LEN]
            .copy_from_slice(&over_u32_max.to_be_bytes());

        let err = GitShardPayload::decode(&encoded)
            .expect_err("pack_exec_workers above u32::MAX must be rejected on decode");
        assert!(
            matches!(
                err,
                GitShardPayloadDecodeError::PackExecWorkersTooLarge { workers }
                    if workers == over_u32_max
            ),
            "expected PackExecWorkersTooLarge, got {err:?}"
        );
    }

    #[test]
    fn encode_golden_vector() {
        // Fixed synthetic path avoids tempdir non-determinism.
        let repo_key = RepoKey::for_local_path(b"/golden/repo").expect("repo key");
        let payload = GitShardPayload::new(
            tenant(0xAB),
            GitRepoTarget::new(repo_key.clone(), RepoLocator::local_path("/golden/repo")),
            derive_repo_id(tenant(0xAB), &repo_key),
            NormalizedGitSelection::DefaultBranchOnly,
            GitScanMode::OdbBlobFast,
            GitMergeStrategy::AllParents,
            GitExecutionLimits::default(),
        );
        let encoded = payload.encode().expect("encode golden payload");

        // Pin the exact wire bytes. Any change to field order, tag values,
        // or length-prefix endianness will fail this test, alerting that
        // stored connector_extra blobs will diverge.
        let hex = encoded
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        const EXPECTED_HEX: &str = "ababababababababababababababababababababababababababababababababbc1be4db17dee94f0000000d012f676f6c64656e2f7265706f010000000c2f676f6c64656e2f7265706f00000100000000000000000000000000000000000000";

        assert_eq!(
            hex, EXPECTED_HEX,
            "wire format changed \u{2014} stored connector_extra blobs will diverge"
        );
    }
}
