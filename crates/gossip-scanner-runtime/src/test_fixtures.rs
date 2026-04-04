//! Shared test fixtures for the gossip-scanner-runtime crate.
//!
//! This module centralizes reusable test data builders and git repository
//! setup helpers so runtime test modules share one command/assertion path.

use std::path::Path;
use std::process::Command;

use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{
        FenceEpoch, LogicalTime, ObjectVersionId, PolicyHash, RuleFingerprint, RunId, ShardId,
        StableItemId, TenantId, TenantSecretKey, derive_rule_fingerprint,
    },
    persistence::WriteContext,
};
use scanner_scheduler::store::FsFindingRecord;

use crate::{
    commit_model::CompletedUnit,
    result_translation::{ItemResult, PersistenceTranslation, ScanTiming, translate_item_result},
};

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

/// Run `git` inside `dir`, assert the command succeeds, and return the raw
/// process output. Both [`run_git_in`] and [`run_git_in_stdout`] delegate here.
fn assert_git_output(dir: &Path, args: &[&str]) -> std::process::Output {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git command failed: git -C {} {}\nstdout:{}\nstderr:{}",
        dir.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

/// Run `git` inside `dir` and assert the command succeeds.
pub fn run_git_in(dir: &Path, args: &[&str]) {
    assert_git_output(dir, args);
}

/// Run `git` inside `dir`, assert success, and return trimmed stdout.
pub fn run_git_in_stdout(dir: &Path, args: &[&str]) -> String {
    let output = assert_git_output(dir, args);
    String::from_utf8(output.stdout)
        .expect("git stdout should be valid UTF-8")
        .trim()
        .to_owned()
}

/// Initialize a git repository with the configured author identity.
pub fn init_git_repo(dir: &Path, email: &str, name: &str) {
    run_git_in(dir, &["init", "-q"]);
    run_git_in(dir, &["config", "user.email", email]);
    run_git_in(dir, &["config", "user.name", name]);
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

pub(crate) fn item_key(item_suffix: u8) -> ItemKey {
    ItemKey::try_from_slice(&[b't', b'/', item_suffix]).unwrap()
}

pub(crate) fn scan_item(item_suffix: u8) -> ScanItem {
    let item_ref = ItemRef::try_from_vec(vec![b'r', item_suffix]).unwrap();
    let path = format!("tenant/repo/file-{item_suffix}.txt");
    let url = format!("https://example.invalid/{item_suffix}");

    ScanItem::new(
        item_key(item_suffix),
        item_ref,
        StableItemId::from_bytes([item_suffix; 32]),
        VersionId::Strong(ObjectVersionId::from_bytes(
            [item_suffix.wrapping_add(1); 32],
        )),
    )
    .with_location(Location::try_new(path, Some(url)).unwrap())
}

pub(crate) fn completed_unit(sequence_no: u64, item_suffix: u8) -> CompletedUnit {
    CompletedUnit::ordered_content(sequence_no, Cursor::with_last_key(item_key(item_suffix)))
}

pub(crate) fn scanned_translation_with(
    write_context: WriteContext,
    item_suffix: u8,
    timing_offset: u64,
    findings: &[FsFindingRecord],
) -> PersistenceTranslation {
    let item = scan_item(item_suffix);
    translate_item_result(
        write_context,
        &tenant_secret_key(),
        &item,
        128,
        timing_with_offset(timing_offset),
        ItemResult::Scanned { findings },
        &test_rule_fingerprint,
    )
    .expect("translation should succeed")
}

pub(crate) fn scanned_translation(
    write_context: WriteContext,
    item_suffix: u8,
    timing_offset: u64,
) -> PersistenceTranslation {
    scanned_translation_with(
        write_context,
        item_suffix,
        timing_offset,
        &[
            finding(7, 10, 20, item_suffix),
            finding(9, 30, 45, item_suffix.wrapping_add(10)),
        ],
    )
}

pub(crate) fn clean_scanned_translation(
    write_context: WriteContext,
    item_suffix: u8,
    timing_offset: u64,
) -> PersistenceTranslation {
    scanned_translation_with(write_context, item_suffix, timing_offset, &[])
}
