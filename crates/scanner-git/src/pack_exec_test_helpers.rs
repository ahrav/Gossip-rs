//! Shared test helpers for pack execution test suites.
//!
//! Provides common trait implementations and factory functions used across
//! `pack_exec`, `metamorphic_tests`, and other pack-related test modules.

use std::collections::HashMap;

use crate::byte_arena::ByteRef;
use crate::object_id::OidBytes;
use crate::pack_candidates::PackCandidate;
use crate::pack_decode::PackDecodeLimits;
use crate::pack_exec::{ExternalBase, ExternalBaseProvider, PackExecError, PackObjectSink};
use crate::tree_candidate::{CandidateContext, ChangeKind};

/// Default decode limits for pack execution tests.
///
/// `max_header_bytes = 64`, `max_object_bytes = 1024`,
/// `max_delta_bytes = 1024`. Matches the inner limits of
/// [`multi_pack_test_helpers::test_limits`](super::multi_pack_test_helpers::test_limits).
pub(crate) const TEST_DECODE_LIMITS: PackDecodeLimits = PackDecodeLimits::new(64, 1024, 1024);

/// Collects resolved blob bytes keyed by OID.
///
/// Panics if the same OID is emitted with different content, catching
/// accidental nondeterminism in the execution pipeline.
#[derive(Default)]
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
        if let Some(prev) = self.blobs.get(&candidate.oid) {
            assert_eq!(
                prev.as_slice(),
                bytes,
                "duplicate OID emitted with different bytes"
            );
        }
        self.blobs.insert(candidate.oid, bytes.to_vec());
        Ok(())
    }
}

/// Panicking external base provider for tests that should never trigger
/// external lookups.
#[derive(Default)]
pub(crate) struct NoExternal;

impl ExternalBaseProvider for NoExternal {
    fn load_base(&mut self, _oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
        panic!("unexpected external base lookup in test");
    }
}

/// Builds a [`CandidateContext`] with default test values.
///
/// Uses `commit_id = 1`, `parent_idx = 0`, `change_kind = Add`, and
/// zeroed flags. Suitable for any test that does not depend on specific
/// candidate metadata.
pub(crate) fn default_test_ctx(path_ref: ByteRef) -> CandidateContext {
    CandidateContext {
        commit_id: 1,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref,
    }
}
