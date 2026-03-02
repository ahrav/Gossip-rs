//! Benchmark-only re-exports for connector pipeline internals.
//!
//! Gated behind `#[cfg(feature = "bench")]` + `connector-pipeline`.
//! These wrappers expose the barrier primitives to criterion benchmarks
//! without making them part of the public API.

use super::connector_pipeline;
use std::sync::Arc;

/// Opaque handle to a [`PageCompletionBarrier`] for benchmark use.
///
/// Wraps the private barrier type so benchmarks can create, wait on, and
/// measure barrier drain latency without accessing module internals directly.
pub struct BenchBarrier {
    inner: Arc<connector_pipeline::PageCompletionBarrier>,
}

/// Opaque handle to a [`PageItemToken`] for benchmark use.
///
/// Tokens can be sent across threads via [`complete`](Self::complete) or
/// simply dropped (exercising the RAII release path).
pub struct BenchToken {
    inner: Option<connector_pipeline::PageItemToken>,
}

impl BenchBarrier {
    /// Block until all tokens created with this barrier have been released.
    pub fn wait_until_complete(&self) {
        self.inner.wait_until_complete();
    }
}

impl BenchToken {
    /// Explicitly release this token's hold on the barrier.
    pub fn complete(mut self) {
        if let Some(token) = self.inner.take() {
            token.complete();
        }
    }
}

impl Drop for BenchToken {
    fn drop(&mut self) {
        // PageItemToken's own Drop handles release if we haven't called complete.
        // Just drop the inner Option<PageItemToken>.
    }
}

/// Create a barrier and `item_count` tokens, mirroring `track_page_items`.
///
/// Returns `(barrier, tokens)` where each token holds one outstanding count
/// on the barrier. The barrier unblocks when all tokens are released.
pub fn bench_track_page_items(page_id: u64, item_count: usize) -> (BenchBarrier, Vec<BenchToken>) {
    let (barrier, tokens) = connector_pipeline::track_page_items(
        connector_pipeline::PageId::from_raw(page_id),
        item_count,
    );
    let bench_tokens = tokens
        .into_iter()
        .map(|t| BenchToken { inner: Some(t) })
        .collect();
    (BenchBarrier { inner: barrier }, bench_tokens)
}
