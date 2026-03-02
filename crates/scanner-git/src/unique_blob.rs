//! Unique blob output types and sink traits.
//!
//! Unique blobs are emitted after global dedupe and seen filtering. The
//! `CandidateContext` holds a `path_ref` that points into a short-lived
//! `ByteArena` provided on each `emit` call; sinks must copy or re-intern
//! path bytes if they need to retain them beyond the call.

use super::byte_arena::ByteArena;
use super::errors::SpillError;
use super::object_id::OidBytes;
use super::tree_candidate::CandidateContext;

/// Unique blob with canonical context and path reference.
///
/// The `ctx.path_ref` points into the `ByteArena` passed to `emit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniqueBlob {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context, including the path reference.
    pub ctx: CandidateContext,
}

/// Sink for unique blobs.
///
/// # Contract
/// - `emit` is called once per unique, unseen blob.
/// - `paths` is only valid for the duration of the call.
/// - Implementations must not retain `ByteRef` values without copying.
pub trait UniqueBlobSink {
    /// Receives a unique, unseen blob.
    fn emit(&mut self, blob: &UniqueBlob, paths: &ByteArena) -> Result<(), SpillError>;

    /// Called when all blobs have been emitted.
    fn finish(&mut self) -> Result<(), SpillError> {
        Ok(())
    }
}

/// Collecting sink for tests and diagnostics.
///
/// Stores owned path bytes so the results outlive the source arena.
#[derive(Debug, Default)]
pub struct CollectingUniqueBlobSink {
    /// Collected blobs (with owned paths).
    pub blobs: Vec<CollectedUniqueBlob>,
}

/// A collected unique blob with owned path bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedUniqueBlob {
    pub oid: OidBytes,
    pub ctx: CandidateContext,
    pub path: Vec<u8>,
}

impl UniqueBlobSink for CollectingUniqueBlobSink {
    fn emit(&mut self, blob: &UniqueBlob, paths: &ByteArena) -> Result<(), SpillError> {
        let path = paths.get(blob.ctx.path_ref).to_vec();
        self.blobs.push(CollectedUniqueBlob {
            oid: blob.oid,
            ctx: blob.ctx,
            path,
        });
        Ok(())
    }
}
