//! Shared git-backed helpers for integration and simulation test targets.

use std::collections::HashMap;

use scanner_git::{
    ByteRef, CandidateContext, ChangeKind, OidBytes, PackCandidate, PackExecError, PackObjectSink,
};

pub(crate) use gossip_stdx::git_test_support::{
    decode_hex, git_available, git_stdout, init_git_repo, run_git,
};
// Used by the integration target but not the simulation target.
#[allow(unused_imports)]
pub(crate) use gossip_stdx::git_test_support::git_output_raw;

pub(crate) fn oid_from_hex(hex: &str) -> OidBytes {
    OidBytes::from_slice(&decode_hex(hex.trim()))
}

/// Sink that collects decoded blob bytes by OID.
///
/// Panics on duplicate OID emission — a duplicate indicates a bug in the
/// plan builder or executor since each candidate maps to exactly one pack.
// Integration test support compiles per-target; rustc cannot see cross-module
// usage within the test harness, producing false dead_code warnings.
#[derive(Default)]
#[allow(dead_code)]
pub(crate) struct CollectingSink {
    pub(crate) blobs: HashMap<OidBytes, Vec<u8>>,
}

impl PackObjectSink for CollectingSink {
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        _path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let prev = self.blobs.insert(candidate.oid, bytes.to_vec());
        assert!(prev.is_none(), "duplicate emit for OID {}", candidate.oid);
        Ok(())
    }
}

/// Returns a fixed-value `CandidateContext` suitable for test fixtures.
#[allow(dead_code)] // see comment on CollectingSink above
pub(crate) fn ctx(path_ref: ByteRef) -> CandidateContext {
    CandidateContext {
        commit_id: 1,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref,
    }
}
