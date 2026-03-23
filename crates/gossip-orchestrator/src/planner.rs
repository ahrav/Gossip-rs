//! Deterministic initial shard geometry planning for filesystem requests.
//!
//! The planner deliberately emits one startup shard per normalized request.
//! Any later fan-out comes from coordination split flows after the worker
//! makes progress, not from submission-time pre-sharding.

use crate::request::NormalizedFilesystemRequest;

/// Geometry-only bounds for one planned initial shard.
///
/// This type carries only key-range geometry. Shard identifiers, connector
/// metadata, cursor state, and manifest rows are downstream registration
/// concerns.
///
/// Key-range bounds follow the [`ShardSpec`] convention: empty slices mean
/// unbounded in that direction. Downstream lowering to [`InitialShardInput`]
/// must translate unbounded geometry to connector-specific finite bounds
/// before manifest registration, which rejects unbounded ranges.
///
/// [`ShardSpec`]: gossip_coordination::ShardSpec
/// [`InitialShardInput`]: gossip_coordination::InitialShardInput
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialShardGeometry {
    key_range_start: &'static [u8],
    key_range_end: &'static [u8],
}

impl InitialShardGeometry {
    /// Geometry covering the full connector keyspace (unbounded).
    ///
    /// Empty slices follow the [`ShardSpec::unbounded()`] convention: no lower
    /// bound and no upper bound. See the struct-level docs for lowering
    /// requirements.
    ///
    /// [`ShardSpec::unbounded()`]: gossip_coordination::ShardSpec::unbounded
    #[must_use]
    pub const fn full_connector_keyspace() -> Self {
        Self {
            key_range_start: &[],
            key_range_end: &[],
        }
    }

    /// Returns `true` if the lower bound is unbounded (empty).
    #[must_use]
    pub fn is_start_unbounded(&self) -> bool {
        self.key_range_start.is_empty()
    }

    /// Returns `true` if the upper bound is unbounded (empty).
    #[must_use]
    pub fn is_end_unbounded(&self) -> bool {
        self.key_range_end.is_empty()
    }

    /// Inclusive lower bound of the planned key range, or empty for unbounded.
    #[must_use]
    pub fn key_range_start(&self) -> &[u8] {
        self.key_range_start
    }

    /// Exclusive upper bound of the planned key range, or empty for unbounded.
    #[must_use]
    pub fn key_range_end(&self) -> &[u8] {
        self.key_range_end
    }
}

/// Geometry-only startup plan for one normalized filesystem request.
///
/// The normalized request preserves the canonical root and explicit source
/// mode (`single_file` versus `directory_root`). The planner keeps that
/// request attached so later payload and registration stages do not need to
/// re-parse raw input to recover source semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemInitialShardPlan {
    request: NormalizedFilesystemRequest,
    initial_shard: InitialShardGeometry,
}

impl FilesystemInitialShardPlan {
    /// The normalized request that this geometry was derived from.
    #[must_use]
    pub fn request(&self) -> &NormalizedFilesystemRequest {
        &self.request
    }

    /// The single startup shard geometry.
    #[must_use]
    pub fn initial_shard(&self) -> InitialShardGeometry {
        self.initial_shard
    }

    /// Slice view of the planned startup geometries.
    ///
    /// Returns a single-element slice. The slice surface keeps lowering
    /// code uniform without introducing startup fan-out.
    #[must_use]
    pub fn shard_geometries(&self) -> &[InitialShardGeometry] {
        std::slice::from_ref(&self.initial_shard)
    }
}

/// Plan deterministic initial shard geometry for one normalized filesystem request.
///
/// Both `single_file` and `directory_root` requests start with one full-range
/// shard. The normalized request retains the source-mode distinction for
/// later payload and runtime hydration work.
#[must_use]
pub fn plan_filesystem_initial_shards(
    request: NormalizedFilesystemRequest,
) -> FilesystemInitialShardPlan {
    FilesystemInitialShardPlan {
        request,
        initial_shard: InitialShardGeometry::full_connector_keyspace(),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::request::{FilesystemRequest, FilesystemSourceMode};
    use crate::test_support::run_config;

    #[test]
    fn single_file_requests_plan_one_full_range_shard() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let normalized = FilesystemRequest::single_file(&file_path, run_config())
            .normalize()
            .expect("single-file request should normalize");
        let plan = plan_filesystem_initial_shards(normalized.clone());

        assert_eq!(plan.request(), &normalized);
        assert_eq!(plan.request().mode(), FilesystemSourceMode::SingleFile);
        assert_eq!(
            plan.request().relative_namespace_name(),
            Some(OsStr::new("scan-target.txt"))
        );
        assert_eq!(plan.shard_geometries().len(), 1);
        let geom = plan.initial_shard();
        assert!(geom.is_start_unbounded());
        assert!(geom.is_end_unbounded());
        assert_eq!(geom.key_range_start(), b"");
        assert_eq!(geom.key_range_end(), b"");
    }

    #[test]
    fn directory_root_requests_plan_one_full_range_root_shard() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("scan-root");
        fs::create_dir(&root).expect("create root directory");

        let normalized = FilesystemRequest::directory_root(&root, run_config())
            .normalize()
            .expect("directory-root request should normalize");
        let plan = plan_filesystem_initial_shards(normalized.clone());

        assert_eq!(plan.request(), &normalized);
        assert_eq!(plan.request().mode(), FilesystemSourceMode::DirectoryRoot);
        assert_eq!(plan.request().relative_namespace_name(), None);
        assert_eq!(plan.shard_geometries().len(), 1);
        let geom = plan.initial_shard();
        assert!(geom.is_start_unbounded());
        assert!(geom.is_end_unbounded());
        assert_eq!(geom.key_range_start(), b"");
        assert_eq!(geom.key_range_end(), b"");
    }

    #[test]
    fn equivalent_requests_plan_identically() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let canonical = FilesystemRequest::single_file(&file_path, run_config())
            .normalize()
            .expect("canonical request should normalize");
        let dotted = FilesystemRequest::single_file(
            file_path
                .parent()
                .expect("file has parent")
                .join(".")
                .join("scan-target.txt"),
            run_config(),
        )
        .normalize()
        .expect("dotted request should normalize");

        assert_eq!(
            plan_filesystem_initial_shards(canonical),
            plan_filesystem_initial_shards(dotted)
        );
    }

    #[test]
    fn planner_does_not_emit_startup_fan_out() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("alpha.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let directory_root = dir.path().join("scan-root");
        fs::create_dir(&directory_root).expect("create root directory");

        let file_plan = plan_filesystem_initial_shards(
            FilesystemRequest::single_file(&file_path, run_config())
                .normalize()
                .expect("single-file request should normalize"),
        );
        let directory_plan = plan_filesystem_initial_shards(
            FilesystemRequest::directory_root(&directory_root, run_config())
                .normalize()
                .expect("directory-root request should normalize"),
        );

        assert_eq!(file_plan.shard_geometries().len(), 1);
        assert_eq!(directory_plan.shard_geometries().len(), 1);
        assert_eq!(file_plan.initial_shard(), directory_plan.initial_shard());
    }
}
