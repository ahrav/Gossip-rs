use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use regex::bytes::Regex;
use scanner_engine::{Engine, FileId, Finding, RuleSpec, ValidatorKind, demo_engine, demo_tuning};
use std::io::{self, Write};

fn write_temp_file(bytes: &[u8]) -> io::Result<tempfile::NamedTempFile> {
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    Ok(tmp)
}

/// File-backed chunked scanner used by integration tests.
///
/// Mirrors runtime overlap semantics:
/// - scan chunk buffer = overlap prefix + new payload
/// - base offset points at chunk buffer start in file coordinates
/// - findings fully inside overlap prefix are dropped per chunk
fn scan_file_chunked_materialized(
    engine: &Engine,
    path: &std::path::Path,
    chunk_size: usize,
) -> io::Result<Vec<Finding>> {
    let bytes = std::fs::read(path)?;
    let overlap = engine.required_overlap();

    let mut scratch = engine.new_scratch();
    let mut out = Vec::new();

    let mut tail = vec![0u8; overlap];
    let mut tail_len = 0usize;
    let mut offset = 0usize;

    while offset < bytes.len() {
        let read_len = (bytes.len() - offset).min(chunk_size);

        let payload = &bytes[offset..offset + read_len];
        let mut chunk = Vec::with_capacity(tail_len + payload.len());
        chunk.extend_from_slice(&tail[..tail_len]);
        chunk.extend_from_slice(payload);

        let base_offset = (offset.saturating_sub(tail_len)) as u64;
        engine.scan_chunk_into(&chunk, FileId(0), base_offset, &mut scratch);

        // New bytes begin at the current file offset.
        scratch.drop_prefix_findings(offset as u64);
        engine.drain_findings_materialized(&mut scratch, &mut out);

        let total_len = chunk.len();
        let keep = overlap.min(total_len);
        if keep > 0 {
            tail[..keep].copy_from_slice(&chunk[total_len - keep..]);
        }
        tail_len = keep;
        offset += read_len;
    }

    Ok(out)
}

fn toy_rule_x() -> RuleSpec {
    RuleSpec {
        name: "toy-token",
        anchors: &[b"X"],
        radius: 0,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        offline_validation: None,
        uuid_format_secret: false,
        secret_group: None,
        min_confidence: None,
        re: Regex::new("X").expect("toy regex should compile"),
    }
}

#[test]
fn scan_file_chunked_materializes_provenance_across_chunks() -> io::Result<()> {
    let engine = demo_engine();

    // Base64(UTF16LE(aws-key)) so the finding is transform-derived and carries provenance.
    let aws = b"AKIAIOSFODNN7ABCDEFG";
    let mut utf16le = Vec::with_capacity(aws.len() * 2);
    for &b in aws {
        utf16le.push(b);
        utf16le.push(0);
    }
    let b64 = STANDARD.encode(&utf16le);

    let mut buf = vec![b'!'; 17];
    buf.extend_from_slice(b64.as_bytes());
    buf.extend(vec![b'!'; 17]);

    let tmp = write_temp_file(&buf)?;
    let findings = scan_file_chunked_materialized(&engine, tmp.path(), 32)?;

    let aws_hits: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.rule == "aws-access-token")
        .collect();
    assert!(!aws_hits.is_empty(), "expected aws-access-token detection");
    assert!(
        aws_hits.iter().any(|f| !f.decode_steps.is_empty()),
        "expected transform-derived provenance decode steps"
    );

    Ok(())
}

#[test]
fn scan_file_chunked_drops_prefix_duplicates() -> io::Result<()> {
    let engine = Engine::new(vec![toy_rule_x()], Vec::new(), demo_tuning());

    let mut buf = vec![b'A'; 6];
    buf[3] = b'X'; // Last byte of first 4-byte payload chunk.

    let tmp = write_temp_file(&buf)?;
    let findings = scan_file_chunked_materialized(&engine, tmp.path(), 4)?;

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, "toy-token");
    assert_eq!(findings[0].root_span_hint, 3..4);

    Ok(())
}

/// `root_span_hint` must remain file-absolute even when a finding lands past
/// the first 1 MiB chunk boundary (`DEFAULT_CHUNK_BYTES = 1 << 20`).
///
/// These root-hint offsets later feed persistence identity derivation via
/// `PersistenceFinding::blob_offset_start/blob_offset_end`, so chunk
/// boundaries must not shift them.
#[test]
fn scan_file_chunked_realistic_multi_chunk_root_hint_is_file_absolute() -> io::Result<()> {
    // Use a permissive single-char rule so the secret match is independent
    // of surrounding content — the padding is a random byte that cannot
    // trigger the rule.
    let engine = Engine::new(vec![toy_rule_x()], Vec::new(), demo_tuning());

    // 2 MiB file with the secret byte 'X' at an absolute offset past the
    // first 1 MiB chunk boundary. `DEFAULT_CHUNK_BYTES = 1 << 20` in
    // scanner-git; the integration test uses an explicit chunk size below
    // matching that value so the test exercises the same boundary logic.
    const BLOB_SIZE: usize = 2 * 1024 * 1024;
    const SECRET_OFFSET: usize = 1_500_000;
    const CHUNK_SIZE: usize = 1 << 20;

    let mut buf = vec![b'A'; BLOB_SIZE];
    buf[SECRET_OFFSET] = b'X';

    let tmp = write_temp_file(&buf)?;
    let findings = scan_file_chunked_materialized(&engine, tmp.path(), CHUNK_SIZE)?;

    let x_hits: Vec<&Finding> = findings.iter().filter(|f| f.rule == "toy-token").collect();
    assert_eq!(x_hits.len(), 1, "expected exactly one toy-token hit");
    assert_eq!(
        x_hits[0].root_span_hint,
        SECRET_OFFSET..(SECRET_OFFSET + 1),
        "root_span_hint must be file-absolute for findings past the first chunk boundary",
    );

    Ok(())
}
