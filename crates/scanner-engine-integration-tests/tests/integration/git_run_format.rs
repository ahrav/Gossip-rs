//! Integration test for spill run format round-trip.
//!
//! Ensures sorted + deduped candidate chunks serialize to a run file and
//! deserialize back with canonical ordering and intact context fields.

use std::io::Cursor;

use scanner_git::OidBytes;
use scanner_git::{
    CandidateChunk, ChangeKind, RunHeader, RunReader, RunRecord, RunWriter, SpillLimits,
};

#[test]
fn run_format_round_trip() {
    let limits = SpillLimits::RESTRICTIVE;
    let mut chunk = CandidateChunk::new(&limits, 20);

    let oid_a = OidBytes::sha1([0x01; 20]);
    let oid_b = OidBytes::sha1([0x02; 20]);

    chunk
        .push(oid_b, b"b.txt", 2, 0, ChangeKind::Modify, 1, 2)
        .unwrap();
    chunk
        .push(oid_a, b"a.txt", 1, 0, ChangeKind::Add, 3, 4)
        .unwrap();
    chunk
        .push(oid_a, b"a.txt", 1, 0, ChangeKind::Add, 3, 4)
        .unwrap();

    chunk.sort_and_dedupe();

    let mut buffer = Vec::new();
    let header = RunHeader::new(20, chunk.len() as u32).unwrap();
    let mut writer = RunWriter::new(&mut buffer, header).unwrap();
    for cand in chunk.iter_resolved() {
        writer.write_resolved(&cand).unwrap();
    }
    writer.finish().unwrap();

    let mut reader = RunReader::new(Cursor::new(buffer), limits.max_path_len).unwrap();
    let mut records = Vec::new();
    while let Some(record) = reader.next_record().unwrap() {
        records.push(record);
    }

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].oid, oid_a);
    assert_eq!(records[0].path, b"a.txt");
    assert_eq!(records[1].oid, oid_b);
    assert_eq!(records[1].path, b"b.txt");

    // Ensure canonical order matches RunRecord ordering.
    let mut sorted = records.clone();
    sorted.sort();
    assert_eq!(records, sorted);

    // Ensure record fields round-trip.
    let rec = &records[0];
    assert_eq!(rec.ctx.commit_id, 1);
    assert_eq!(rec.ctx.change_kind, ChangeKind::Add);
    assert_eq!(rec.ctx.ctx_flags, 3);
    assert_eq!(rec.ctx.cand_flags, 4);

    let _ = RunRecord {
        oid: rec.oid,
        ctx: rec.ctx,
        path: rec.path.clone(),
    };
}
