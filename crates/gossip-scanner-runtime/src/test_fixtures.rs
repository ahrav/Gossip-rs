//! Shared test fixtures for the gossip-scanner-runtime crate.

use gossip_contracts::{
    identity::{
        FenceEpoch, LogicalTime, PolicyHash, RuleFingerprint, RunId, ShardId, TenantId,
        TenantSecretKey, derive_rule_fingerprint,
    },
    persistence::WriteContext,
};
use scanner_scheduler::store::FsFindingRecord;

use crate::result_translation::ScanTiming;

pub(crate) fn test_rule_fingerprint(rule_id: u32) -> RuleFingerprint {
    let name = format!("test-rule-{rule_id}");
    derive_rule_fingerprint(&name)
}

pub(crate) fn tenant_secret_key() -> TenantSecretKey {
    TenantSecretKey::from_bytes([0x99; 32])
}

pub(crate) fn write_context() -> WriteContext {
    write_context_with_epoch(55)
}

pub(crate) fn write_context_with_epoch(fence_epoch_raw: u64) -> WriteContext {
    WriteContext::new(
        TenantId::from_bytes([0x11; 32]),
        PolicyHash::from_bytes([0x22; 32]),
        RunId::from_raw(33),
        ShardId::from_raw(44),
        FenceEpoch::from_raw(fence_epoch_raw),
    )
}

pub(crate) fn timing() -> ScanTiming {
    timing_with_offset(0)
}

pub(crate) fn timing_with_offset(offset: u64) -> ScanTiming {
    ScanTiming::new(
        LogicalTime::from_raw(1_000 + offset),
        LogicalTime::from_raw(2_000 + offset),
    )
}

/// Spin-polls `predicate` at 5ms intervals for up to 10s (2 000 iterations).
/// Panics if the condition is never satisfied.
pub(crate) fn wait_until(mut predicate: impl FnMut() -> bool) {
    for _ in 0..2_000 {
        if predicate() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!("condition was not satisfied before timeout");
}

pub(crate) fn finding(
    rule_id: u32,
    span_start: u64,
    span_end: u64,
    hash_seed: u8,
) -> FsFindingRecord {
    FsFindingRecord {
        rule_id,
        root_hint_start: span_start,
        root_hint_end: span_end,
        span_start,
        span_end,
        norm_hash: [hash_seed; 32],
        confidence_score: 7,
    }
}
