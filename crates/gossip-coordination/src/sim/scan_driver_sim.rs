//! Deterministic synthetic scan outcome generator for composition simulation.
//!
//! Produces [`DoneLedgerRecord`]s from PRNG-driven parameters, modeling the
//! abstract result of scanning a shard without filesystem coupling. Each record
//! carries provenance derived from the lease that claimed the shard, bridging
//! the coordinator's `(RunId, ShardId)` key space to the done-ledger's
//! `(TenantId, PolicyHash, OvidHash)` key space.
//!
//! Used by [`CompositionSim`](super::composition::CompositionSim) to drive
//! the claim-scan-complete loop deterministically.

use rand::Rng;

use gossip_contracts::identity::{FenceEpoch, LogicalTime, PolicyHash};
use gossip_contracts::persistence::{
    DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus,
    OvidHash,
};

use crate::sim::SimContext;
use crate::Lease;

// ---------------------------------------------------------------------------
// ScanOutcome
// ---------------------------------------------------------------------------

/// Result of a synthetic scan: done-ledger records and a cursor position.
///
/// The `records` vector contains one [`DoneLedgerRecord`] per scanned item,
/// each carrying provenance from the lease. `cursor_bytes` is a random cursor
/// value for the coordinator's `complete()` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Done-ledger records produced by the scan.
    pub records: Vec<DoneLedgerRecord>,
    /// Cursor bytes for the coordinator `complete()` call.
    pub cursor_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Generate a synthetic scan outcome from PRNG state.
///
/// Given a lease (for provenance), a policy hash, and a pool of object-version
/// hashes to select from, produces N records with random statuses and metrics.
/// The number of items is drawn from `items_range`.
///
/// When `fence_override` is `Some`, the provenance carries the overridden fence
/// instead of the lease's actual epoch. This models a worker writing done-ledger
/// records using credentials from a prior lease acquisition (stale provenance).
///
/// When `cursor_bounds` is `Some((lo, hi))`, the cursor is generated as a
/// single byte within `[lo, hi)` to satisfy coordinator cursor validation.
/// When `None`, fully random 4-16 byte cursors are generated (suitable for
/// tests that do not validate the cursor against shard bounds).
///
/// # PRNG ordering
///
/// Calls `context.rng()` in a fixed sequence:
/// 1. Item count (1 draw)
/// 2. Per item:
///    a. ovid index (1 draw)
///    b. status roll (1 draw); if `ScannedWithFindings`, findings_count (1 draw)
///    c. bytes_scanned (1 draw)
///    Draws per item: 3 or 4 depending on status branch.
/// 3. Cursor length (1 draw)
/// 4. Cursor bytes (length draws)
///
/// When `cursor_bounds` is `Some`, steps 3-4 are replaced by a single draw
/// for the bounded byte.
///
/// Appending new draws at the end preserves determinism for existing seeds.
pub fn generate_scan_outcome(
    context: &mut SimContext,
    lease: &Lease,
    policy: PolicyHash,
    ovid_pool: &[OvidHash],
    items_range: core::ops::RangeInclusive<usize>,
    now: LogicalTime,
    fence_override: Option<FenceEpoch>,
    cursor_bounds: Option<(u8, u8)>,
) -> ScanOutcome {
    assert!(!ovid_pool.is_empty(), "ovid_pool must not be empty");

    let fence = fence_override.unwrap_or(lease.fence());
    let n = context.rng().random_range(items_range);
    let mut records = Vec::with_capacity(n);

    for _ in 0..n {
        let ovid_idx = context.rng().random_range(0..ovid_pool.len());
        let ovid = ovid_pool[ovid_idx];

        let (status, findings_count, error_code) = random_status_and_findings(context);
        let bytes_scanned: u64 = context.rng().random_range(100..10_000);

        let key = DoneLedgerKey::new(lease.tenant(), policy, ovid);
        let provenance = DoneLedgerProvenance::new(lease.run(), lease.shard(), fence, now, now);

        // `try_new` validates status/findings consistency; the random_status_and_findings
        // helper guarantees valid combinations, so unwrap is safe here.
        let record = DoneLedgerRecord::try_new(
            key,
            status,
            bytes_scanned,
            findings_count,
            provenance,
            error_code,
        )
        .expect("random_status_and_findings produced an invalid status/findings combination");

        records.push(record);
    }

    let cursor_bytes = match cursor_bounds {
        Some((lo, hi)) if lo < hi => {
            // Bounded: single byte within shard's key range for valid
            // cursor validation by the coordinator.
            let byte = context.rng().random_range(lo..hi);
            vec![byte]
        }
        _ => random_cursor_bytes(context),
    };

    ScanOutcome {
        records,
        cursor_bytes,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pick a random status with weighted distribution and matching findings/error.
///
/// Distribution: 60% ScannedClean, 20% ScannedWithFindings, 8% FailedRetryable,
/// 7% FailedPermanent, 5% Skipped. Weighted toward success to model realistic
/// scan workloads where most objects scan cleanly.
fn random_status_and_findings(
    context: &mut SimContext,
) -> (DoneLedgerStatus, u32, Option<DoneLedgerErrorCode>) {
    let roll: u32 = context.rng().random_range(0..100);

    match roll {
        0..60 => (DoneLedgerStatus::ScannedClean, 0, None),
        60..80 => {
            let findings: u32 = context.rng().random_range(1..=5);
            (DoneLedgerStatus::ScannedWithFindings, findings, None)
        }
        80..88 => {
            let code = DoneLedgerErrorCode::try_new("SIM_RETRYABLE")
                .expect("hardcoded error code is valid");
            (DoneLedgerStatus::FailedRetryable, 0, Some(code))
        }
        88..95 => {
            let code = DoneLedgerErrorCode::try_new("SIM_PERMANENT")
                .expect("hardcoded error code is valid");
            (DoneLedgerStatus::FailedPermanent, 0, Some(code))
        }
        _ => {
            let code =
                DoneLedgerErrorCode::try_new("SIM_SKIPPED").expect("hardcoded error code is valid");
            (DoneLedgerStatus::Skipped, 0, Some(code))
        }
    }
}

/// Generate random cursor bytes (4-16 bytes) for the coordinator `complete()` call.
fn random_cursor_bytes(context: &mut SimContext) -> Vec<u8> {
    let len: usize = context.rng().random_range(4..=16);
    let mut bytes = vec![0u8; len];
    for b in &mut bytes {
        *b = context.rng().random_range(0u8..=255);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossip_contracts::identity::{FenceEpoch, LogicalTime, RunId, ShardId, TenantId, WorkerId};

    fn test_lease() -> Lease {
        Lease::new(
            TenantId::from_bytes([0x01; 32]),
            RunId::from_raw(1),
            ShardId::from_raw(1),
            WorkerId::from_raw(1),
            FenceEpoch::INITIAL,
            LogicalTime::from_raw(100),
        )
    }

    fn test_ovid_pool(ctx: &mut SimContext, n: usize) -> Vec<OvidHash> {
        (0..n)
            .map(|_| {
                let mut bytes = [0u8; 32];
                for b in &mut bytes {
                    *b = ctx.rng().random_range(0u8..=255);
                }
                OvidHash::from_bytes(bytes)
            })
            .collect()
    }

    #[test]
    fn deterministic_across_runs() {
        let mut ctx1 = SimContext::new(42);
        let pool1 = test_ovid_pool(&mut ctx1, 10);
        let lease = test_lease();
        let policy = PolicyHash::from_bytes([0x22; 32]);
        let now = LogicalTime::from_raw(50);

        let out1 = generate_scan_outcome(&mut ctx1, &lease, policy, &pool1, 1..=5, now, None, None);

        let mut ctx2 = SimContext::new(42);
        let pool2 = test_ovid_pool(&mut ctx2, 10);
        let out2 = generate_scan_outcome(&mut ctx2, &lease, policy, &pool2, 1..=5, now, None, None);

        assert_eq!(out1.records.len(), out2.records.len());
        assert_eq!(out1.cursor_bytes, out2.cursor_bytes);
        for (a, b) in out1.records.iter().zip(&out2.records) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn stale_fence_produces_different_provenance() {
        let mut ctx = SimContext::new(99);
        let pool = test_ovid_pool(&mut ctx, 10);
        let lease = test_lease();
        let policy = PolicyHash::from_bytes([0x22; 32]);
        let now = LogicalTime::from_raw(50);
        let stale = FenceEpoch::from_raw(999);

        let out = generate_scan_outcome(
            &mut ctx,
            &lease,
            policy,
            &pool,
            1..=3,
            now,
            Some(stale),
            None,
        );

        for rec in &out.records {
            assert_eq!(rec.provenance().fence_epoch(), stale);
        }
    }
}
