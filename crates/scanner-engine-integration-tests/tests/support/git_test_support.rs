//! Shared git-backed helpers for integration and simulation test targets.

use std::collections::HashMap;

use scanner_git::{
    ByteRef, CandidateContext, ChangeKind, OidBytes, PackCandidate, PackExecError, PackObjectSink,
};

#[allow(unused_imports)]
pub(crate) use gossip_stdx::git_test_support::{
    decode_hex, git_available, git_output_raw, git_stdout, init_git_repo, run_git,
};

pub(crate) fn oid_from_hex(hex: &str) -> OidBytes {
    OidBytes::from_slice(&decode_hex(hex.trim()))
}

/// Sink that collects decoded blob bytes by OID.
///
/// Panics on duplicate OID emission — a duplicate indicates a bug in the
/// plan builder or executor since each candidate maps to exactly one pack.
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

/// Builds a canonical candidate context for tests.
#[allow(dead_code)]
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
