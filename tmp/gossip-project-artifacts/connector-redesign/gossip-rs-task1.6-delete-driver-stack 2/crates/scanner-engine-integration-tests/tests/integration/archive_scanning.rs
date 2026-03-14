//! Archive scanning tests for the local scheduler path.
//!
//! # Scope
//! These tests exercise archive expansion (gzip, tar, tar.gz), virtual path
//! attribution, boundary overlap, and budget enforcement when using the
//! `scheduler::local_fs_owner` execution path.
//!
//! # Assumptions
//! - Findings are emitted as JSONL via the `VecEventOutput`:
//!   `{"type":"finding","source":"fs","path":"...","start":N,"end":N,"rule_id":N,"rule":"...","confidence_score":N}`.
//! - Virtual paths are displayed as `parent::entry`.
//! - Archive bytes are synthesized with minimal headers plus targeted
//!   corruption for ZIP edge cases.

use crc32fast::Hasher as Crc32;
use flate2::Compression;
use flate2::write::GzEncoder;
use scanner_scheduler::FileId;
use scanner_scheduler::NormHash;
use scanner_scheduler::archive::{
    ArchiveSkipReason, EncryptedPolicy, EntrySkipReason, PartialReason, UnsupportedPolicy,
};
use scanner_scheduler::events::EventOutput;
use scanner_scheduler::events::VecEventOutput;
use scanner_scheduler::scheduler::engine_stub::{MockEngine, MockRule};
use scanner_scheduler::scheduler::engine_trait::{
    EngineScratch, FindingRecord, FindingWithHashRecord, ScanEngine,
};
use scanner_scheduler::scheduler::local_fs_owner::{
    LocalConfig, LocalFile, LocalReport, VecFileSource, scan_local,
};
use scanner_scheduler::store::InMemoryStoreProducer;
use scanner_scheduler::store::StoreProducer;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::FileOptions;

#[derive(Debug)]
struct FindingLine {
    path: String,
    start: u64,
}

/// Extract a JSON string value for a given key from a single JSON line.
///
/// This is a minimal parser that handles backslash-escaped quotes.
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let bytes = rest.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        if bytes[end] == b'\\' {
            end += 2;
        } else if bytes[end] == b'"' {
            break;
        } else {
            end += 1;
        }
    }
    Some(rest[..end].to_string())
}

/// Extract a JSON numeric value for a given key from a single JSON line.
fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Parse JSONL finding lines into `(path, start)` pairs.
///
/// This is intentionally lossy: end offsets and rule names are ignored because
/// the tests only assert path attribution and the start position.
fn parse_findings(output: &str) -> Vec<FindingLine> {
    let mut out = Vec::new();
    for line in output.lines() {
        if !line.contains("\"type\":\"finding\"") {
            continue;
        }
        let path = extract_json_string(line, "path").unwrap_or_default();
        let start = extract_json_u64(line, "start").unwrap_or(0);
        out.push(FindingLine { path, start });
    }
    out
}

fn perf_stats_enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

macro_rules! assert_perf {
    ($on:expr, $off:expr, $($arg:tt)*) => {
        if perf_stats_enabled() {
            assert!($on, $($arg)*);
        } else {
            assert!($off, $($arg)*);
        }
    };
}

fn assert_locator(path: &str, kind: char) {
    let needle = format!("@{kind}");
    let idx = path
        .rfind(&needle)
        .unwrap_or_else(|| panic!("expected locator {needle} in path: {path}"));
    let hex = &path[idx + needle.len()..];
    assert!(
        hex.len() >= 16,
        "expected 16 hex digits after locator in path: {path}"
    );
    assert!(
        hex[..16]
            .chars()
            .all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "expected lowercase hex locator in path: {path}"
    );
}

/// Build a payload with `SECRET` starting exactly at `offset`.
fn payload_with_secret_at(offset: usize) -> Vec<u8> {
    let mut payload = vec![b'A'; offset];
    payload.extend_from_slice(b"SECRET");
    payload
}

fn build_gz_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = GzEncoder::new(&mut out, Compression::default());
    enc.write_all(payload).expect("write gz payload");
    enc.finish().expect("finish gz payload");
    out
}

/// Write a gzip file to `path` with the provided payload bytes.
fn write_gz(path: &Path, payload: &[u8]) -> io::Result<()> {
    let f = File::create(path)?;
    let mut enc = GzEncoder::new(f, Compression::default());
    enc.write_all(payload)?;
    enc.finish()?;
    Ok(())
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) -> io::Result<()> {
    let f = File::create(path)?;
    let mut zw = zip::ZipWriter::new(f);
    let opts = FileOptions::<()>::default().compression_method(CompressionMethod::Deflated);
    for (name, payload) in entries {
        zw.start_file(*name, opts)?;
        zw.write_all(payload)?;
    }
    zw.finish()?;
    Ok(())
}

fn write_zip_with_methods(
    path: &Path,
    entries: &[(&str, &[u8], CompressionMethod)],
) -> io::Result<()> {
    let f = File::create(path)?;
    let mut zw = zip::ZipWriter::new(f);
    for (name, payload, method) in entries {
        let opts = FileOptions::<()>::default().compression_method(*method);
        zw.start_file(*name, opts)?;
        zw.write_all(payload)?;
    }
    zw.finish()?;
    Ok(())
}

fn build_zip_single_stored_entry(name: &str, data: &[u8], encrypted_flag: bool) -> Vec<u8> {
    fn u16le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    let name_bytes = name.as_bytes();
    let mut crc = Crc32::new();
    crc.update(data);
    let crc32 = crc.finalize();

    let flags: u16 = if encrypted_flag { 0x0001 } else { 0x0000 };
    let method: u16 = 0; // stored
    let ver: u16 = 20;

    let local_off: u32 = 0;
    let local_hdr_len = 30u32 + name_bytes.len() as u32;
    let data_off = local_hdr_len;
    let cd_off = data_off + data.len() as u32;

    let mut out = Vec::new();

    // Local file header
    out.extend_from_slice(&u32le(0x04034b50));
    out.extend_from_slice(&u16le(ver));
    out.extend_from_slice(&u16le(flags));
    out.extend_from_slice(&u16le(method));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u32le(crc32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u16le(name_bytes.len() as u16));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(data);

    // Central directory header
    let cd_start = out.len() as u32;
    out.extend_from_slice(&u32le(0x02014b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(ver));
    out.extend_from_slice(&u16le(flags));
    out.extend_from_slice(&u16le(method));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u32le(crc32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u16le(name_bytes.len() as u16));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u32le(0));
    out.extend_from_slice(&u32le(local_off));
    out.extend_from_slice(name_bytes);

    let cd_size = (out.len() as u32) - cd_start;

    // EOCD
    out.extend_from_slice(&u32le(0x06054b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(1));
    out.extend_from_slice(&u16le(1));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_off));
    out.extend_from_slice(&u16le(0));

    out
}

struct ZipEntrySpec<'a> {
    name: &'a str,
    data: &'a [u8],
    flags: u16,
    method: u16,
    extra: &'a [u8],
}

fn build_zip_with_specs(specs: &[ZipEntrySpec<'_>]) -> Vec<u8> {
    fn u16le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    let mut out = Vec::new();
    let mut cd = Vec::new();

    for spec in specs {
        let name_bytes = spec.name.as_bytes();
        let extra_len = spec.extra.len() as u16;
        let local_off = out.len() as u32;

        out.extend_from_slice(&u32le(0x04034b50));
        out.extend_from_slice(&u16le(20));
        out.extend_from_slice(&u16le(spec.flags));
        out.extend_from_slice(&u16le(spec.method));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u32le(0));
        out.extend_from_slice(&u32le(spec.data.len() as u32));
        out.extend_from_slice(&u32le(spec.data.len() as u32));
        out.extend_from_slice(&u16le(name_bytes.len() as u16));
        out.extend_from_slice(&u16le(extra_len));
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(spec.extra);
        out.extend_from_slice(spec.data);

        cd.extend_from_slice(&u32le(0x02014b50));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(20));
        cd.extend_from_slice(&u16le(spec.flags));
        cd.extend_from_slice(&u16le(spec.method));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u32le(0));
        cd.extend_from_slice(&u32le(spec.data.len() as u32));
        cd.extend_from_slice(&u32le(spec.data.len() as u32));
        cd.extend_from_slice(&u16le(name_bytes.len() as u16));
        cd.extend_from_slice(&u16le(extra_len));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u32le(0));
        cd.extend_from_slice(&u32le(local_off));
        cd.extend_from_slice(name_bytes);
        cd.extend_from_slice(spec.extra);
    }

    let cd_start = out.len() as u32;
    out.extend_from_slice(&cd);
    let cd_size = cd.len() as u32;

    out.extend_from_slice(&u32le(0x06054b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(specs.len() as u16));
    out.extend_from_slice(&u16le(specs.len() as u16));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_start));
    out.extend_from_slice(&u16le(0));

    out
}

fn build_zip_two_entries(entry1: (&str, &[u8]), entry2: (&str, &[u8])) -> Vec<u8> {
    fn u16le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    let mut out = Vec::new();
    let mut cd = Vec::new();

    for (name, data) in [entry1, entry2] {
        let name_bytes = name.as_bytes();
        let local_off = out.len() as u32;

        out.extend_from_slice(&u32le(0x04034b50));
        out.extend_from_slice(&u16le(20));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u32le(0));
        out.extend_from_slice(&u32le(data.len() as u32));
        out.extend_from_slice(&u32le(data.len() as u32));
        out.extend_from_slice(&u16le(name_bytes.len() as u16));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        cd.extend_from_slice(&u32le(0x02014b50));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(20));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u32le(0));
        cd.extend_from_slice(&u32le(data.len() as u32));
        cd.extend_from_slice(&u32le(data.len() as u32));
        cd.extend_from_slice(&u16le(name_bytes.len() as u16));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u32le(0));
        cd.extend_from_slice(&u32le(local_off));
        cd.extend_from_slice(name_bytes);
    }

    let cd_start = out.len() as u32;
    out.extend_from_slice(&cd);
    let cd_size = cd.len() as u32;

    out.extend_from_slice(&u32le(0x06054b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(2));
    out.extend_from_slice(&u16le(2));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_start));
    out.extend_from_slice(&u16le(0));

    out
}

const TAR_BLOCK_LEN: usize = 512;

/// Write a minimal ustar header for a regular file.
///
/// This is "just enough" for the tar reader in this repo; it does not attempt
/// to be a full tar writer.
fn tar_write_header(buf: &mut [u8; TAR_BLOCK_LEN], name: &str, size: u64, typeflag: u8) {
    buf.fill(0);
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(100);
    buf[0..name_len].copy_from_slice(&name_bytes[..name_len]);
    buf[100..108].copy_from_slice(b"0000777\0");
    buf[108..116].copy_from_slice(b"0000000\0");
    buf[116..124].copy_from_slice(b"0000000\0");
    let mut size_field = [b'0'; 11];
    let mut v = size;
    for i in (0..11).rev() {
        size_field[i] = b'0' + ((v & 7) as u8);
        v >>= 3;
    }
    buf[124..135].copy_from_slice(&size_field);
    buf[135] = 0;
    buf[136..148].copy_from_slice(b"00000000000\0");
    for b in &mut buf[148..156] {
        *b = b' ';
    }
    buf[156] = typeflag;
    buf[257..263].copy_from_slice(b"ustar\0");
    buf[263..265].copy_from_slice(b"00");
    let sum: u32 = buf.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    buf[148..156].copy_from_slice(chk.as_bytes());
}

fn tar_pad(size: usize) -> usize {
    let rem = size % TAR_BLOCK_LEN;
    if rem == 0 { 0 } else { TAR_BLOCK_LEN - rem }
}

/// Build a single-entry tar archive terminated by two zero blocks.
fn build_simple_tar(entry_name: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hdr = [0u8; TAR_BLOCK_LEN];
    tar_write_header(&mut hdr, entry_name, payload.len() as u64, b'0');
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out
}

/// Build a multi-entry tar archive terminated by two zero blocks.
fn build_multi_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, payload) in entries {
        let mut hdr = [0u8; TAR_BLOCK_LEN];
        tar_write_header(&mut hdr, name, payload.len() as u64, b'0');
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);
    }
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out
}

fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    build_multi_tar(entries)
}

fn pax_record_line(key: &str, value: &str) -> Vec<u8> {
    let body = format!("{key}={value}\n");
    let mut len = body.len() + 1;
    loop {
        let len_str = len.to_string();
        let new_len = len_str.len() + 1 + body.len();
        if new_len == len {
            let mut v = Vec::new();
            v.extend_from_slice(len_str.as_bytes());
            v.push(b' ');
            v.extend_from_slice(body.as_bytes());
            return v;
        }
        len = new_len;
    }
}

fn build_tar_with_pax_path(pax_path: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hdr = [0u8; TAR_BLOCK_LEN];

    let record = pax_record_line("path", pax_path);
    tar_write_header(&mut hdr, "PaxHeader", record.len() as u64, b'x');
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&record);
    out.extend_from_slice(&vec![0u8; tar_pad(record.len())]);

    tar_write_header(&mut hdr, "ignored.txt", payload.len() as u64, b'0');
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);

    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out
}

fn build_tar_with_gnu_longname(long_name: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hdr = [0u8; TAR_BLOCK_LEN];

    let mut name_bytes = long_name.as_bytes().to_vec();
    name_bytes.push(0);
    tar_write_header(&mut hdr, "longname", name_bytes.len() as u64, b'L');
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&name_bytes);
    out.extend_from_slice(&vec![0u8; tar_pad(name_bytes.len())]);

    tar_write_header(&mut hdr, "ignored.txt", payload.len() as u64, b'0');
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);

    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out
}

/// Create a `LocalFile` with a size snapshot based on filesystem metadata.
fn file_from_path(path: &Path) -> LocalFile {
    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    LocalFile {
        path: path.to_path_buf(),
        size,
    }
}

/// Archive-enabled config with generous budgets for tests.
///
/// Individual tests override specific limits to exercise budget behavior.
fn cfg_archives_enabled() -> LocalConfig {
    let mut cfg = LocalConfig {
        workers: 1,
        chunk_size: 64,
        ..LocalConfig::default()
    };
    cfg.archive.enabled = true;
    cfg.archive.max_entries_per_archive = 256;
    cfg.archive.max_archive_metadata_bytes = 1 << 20;
    cfg.archive.max_total_uncompressed_bytes_per_archive = 8 << 20;
    cfg.archive.max_total_uncompressed_bytes_per_root = 8 << 20;
    cfg.archive.max_uncompressed_bytes_per_entry = 2 << 20;
    cfg.archive.max_virtual_path_len_per_entry = 256;
    cfg.archive.max_virtual_path_bytes_per_archive = 64 << 10;
    cfg
}

/// Run a local scan with a single "SECRET" rule and return JSONL output + report.
fn run_scan(files: Vec<LocalFile>, mut cfg: LocalConfig) -> (String, LocalReport) {
    let engine = Arc::new(MockEngine::new(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        16,
    ));
    let sink = Arc::new(VecEventOutput::new());
    cfg.event_sink = Arc::clone(&sink) as Arc<dyn EventOutput>;
    let report = scan_local(engine, VecFileSource::new(files), cfg);
    let out = String::from_utf8_lossy(&sink.take()).to_string();
    (out, report)
}

#[derive(Clone, Copy)]
struct DummyFinding;

impl FindingRecord for DummyFinding {
    fn rule_id(&self) -> u32 {
        0
    }
    fn root_hint_start(&self) -> u64 {
        0
    }
    fn root_hint_end(&self) -> u64 {
        0
    }
    fn span_start(&self) -> u64 {
        0
    }
    fn span_end(&self) -> u64 {
        0
    }
    fn dedupe_with_span(&self) -> bool {
        true
    }
    fn confidence_score(&self) -> i8 {
        0
    }
}

impl FindingWithHashRecord for DummyFinding {
    fn norm_hash(&self) -> &NormHash {
        const ZERO: NormHash = [0; 32];
        &ZERO
    }
}

struct IdScratch {
    findings: Vec<DummyFinding>,
}

impl EngineScratch for IdScratch {
    type Finding = DummyFinding;

    fn clear(&mut self) {
        self.findings.clear();
    }

    fn drop_prefix_findings(&mut self, _new_bytes_start: u64) {}

    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
        out.append(&mut self.findings);
    }
}

#[derive(Clone)]
struct IdEngine {
    seen: Arc<Mutex<Vec<FileId>>>,
}

impl ScanEngine for IdEngine {
    type Scratch = IdScratch;

    fn required_overlap(&self) -> usize {
        0
    }

    fn new_scratch(&self) -> Self::Scratch {
        IdScratch {
            findings: Vec::new(),
        }
    }

    fn scan_chunk_into(
        &self,
        _data: &[u8],
        file_id: FileId,
        _base_offset: u64,
        scratch: &mut Self::Scratch,
    ) {
        self.seen.lock().unwrap().push(file_id);
        scratch.clear();
    }

    fn rule_name(&self, _rule_id: u32) -> &str {
        "rule"
    }

    fn max_findings_per_chunk(&self) -> usize {
        4096
    }
}

#[test]
fn zip_module_reexports_counted_read() {
    // Keep `archive::formats::zip::CountedRead` available for downstream users.
    let reader = std::io::Cursor::new(Vec::<u8>::new());
    let counted = scanner_scheduler::archive::formats::zip::CountedRead::new(reader);
    assert_eq!(counted.bytes(), 0);
}

#[test]
fn finds_secret_in_gzip_with_virtual_path() {
    let tmp = TempDir::new().unwrap();
    let gz = tmp.path().join("payload.txt.gz");

    let payload = payload_with_secret_at(12);
    write_gz(&gz, &payload).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&gz)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    assert!(!findings.is_empty(), "expected finding; output: {out}");

    let f = &findings[0];
    assert!(f.path.contains("payload.txt.gz"));
    assert!(f.path.contains("::"));
    assert_eq!(f.start, 12);
}

#[test]
fn gzip_entry_byte_cap_prevents_unbounded_work_and_is_reported() {
    let tmp = TempDir::new().unwrap();
    let gz = tmp.path().join("big.txt.gz");

    let mut payload = Vec::new();
    payload.extend(std::iter::repeat_n(b'A', 64));
    payload.extend_from_slice(b"SECRET\n");
    payload.extend_from_slice(b"tail\n");

    write_gz(&gz, &payload).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_uncompressed_bytes_per_entry = 32;

    let (out, report) = run_scan(vec![file_from_path(&gz)], cfg);
    assert!(
        out.trim().is_empty(),
        "expected no findings due to cap; got: {out}"
    );

    assert_perf!(
        report.metrics.archive.partial_reasons[PartialReason::EntryOutputBudgetExceeded.as_usize()]
            > 0,
        report.metrics.archive.partial_reasons[PartialReason::EntryOutputBudgetExceeded.as_usize()]
            == 0,
        "expected entry output budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn tar_boundary_spanning_secret_once() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("payload.tar");

    let payload = {
        let mut v = Vec::new();
        v.extend_from_slice(b"AAAAA");
        v.extend_from_slice(b"SECRET");
        v.extend_from_slice(b"BBBBBBBBBBBB");
        v
    };
    let tar_bytes = build_simple_tar("x.txt", &payload);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.chunk_size = 6;

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    assert!(
        report.metrics.chunks_scanned >= 2,
        "expected >= 2 chunks, got {}",
        report.metrics.chunks_scanned
    );
    let count = out.matches("secret").count();
    assert_eq!(count, 1, "output: {out}");
}

#[test]
fn finds_secret_in_nested_gz_inside_tar() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("outer.tar");

    let payload = payload_with_secret_at(4);
    let inner_gz = build_gz_bytes(&payload);
    let tar_bytes = build_simple_tar("inner.gz", &inner_gz);
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let f = findings
        .iter()
        .find(|f| f.path.contains("inner.gz"))
        .expect("expected nested gzip finding");
    assert!(f.path.contains("outer.tar::inner.gz"));
    assert!(f.path.contains("::<gunzip>"));
    assert_locator(&f.path, 't');
}

#[test]
fn nested_gzip_boundary_spanning_secret_once() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("outer.tar");

    let payload = {
        let mut v = Vec::new();
        v.extend_from_slice(b"AAAAA");
        v.extend_from_slice(b"SECRET");
        v.extend_from_slice(b"BBBBBBBBBBBB");
        v
    };
    let inner_gz = build_gz_bytes(&payload);
    let tar_bytes = build_simple_tar("inner.gz", &inner_gz);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.chunk_size = 6;

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    assert!(
        report.metrics.chunks_scanned >= 2,
        "expected >= 2 chunks, got {}",
        report.metrics.chunks_scanned
    );
    let count = out.matches("secret").count();
    assert_eq!(count, 1, "output: {out}");
}

#[test]
fn nested_zip_in_tar_is_not_expanded_and_is_counted() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("outer.tar");

    let mut zip_bytes = Vec::new();
    {
        use zip::CompressionMethod;
        use zip::write::FileOptions;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_bytes));
        let opt = FileOptions::<()>::default().compression_method(CompressionMethod::Deflated);
        w.start_file("notes.txt", opt).unwrap();
        w.write_all(b"no secrets here").unwrap();
        w.finish().unwrap();
    }

    let tar_bytes = build_simple_tar("inner.zip", &zip_bytes);
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    assert!(out.trim().is_empty(), "expected no findings; got: {out}");

    let idx = ArchiveSkipReason::NeedsRandomAccessNoSpill.as_usize();
    assert_perf!(
        report.metrics.archive.archive_skip_reasons[idx] > 0,
        report.metrics.archive.archive_skip_reasons[idx] == 0,
        "expected needs_random_access_no_spill to be counted: {:?}",
        report.metrics.archive
    );
}

#[test]
fn tar_path_budget_exceeded_is_reported() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("payload.tar");

    let payload = b"hello SECRET world\n";
    let tar_bytes = build_multi_tar(&[("first.txt", payload), ("second.txt", payload)]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_virtual_path_len_per_entry = 8;
    cfg.archive.max_virtual_path_bytes_per_archive = 8;

    let (_out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    assert_perf!(
        report.metrics.archive.partial_reasons[PartialReason::PathBudgetExceeded.as_usize()] > 0,
        report.metrics.archive.partial_reasons[PartialReason::PathBudgetExceeded.as_usize()] == 0,
        "expected path budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_boundary_spanning_secret_once() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("payload.zip");

    let payload = {
        let mut v = Vec::new();
        v.extend_from_slice(b"AAAAA");
        v.extend_from_slice(b"SECRET");
        v.extend_from_slice(b"BBBBBBBBBBBB");
        v
    };
    write_zip(&zip_path, &[("x.txt", payload.as_slice())]).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.chunk_size = 6;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    assert!(
        report.metrics.chunks_scanned >= 2,
        "expected >= 2 chunks, got {}",
        report.metrics.chunks_scanned
    );
    let count = out.matches("secret").count();
    assert_eq!(count, 1, "output: {out}");
}

#[test]
fn zip_respects_entry_output_budget() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("payload.zip");

    let payload = b"hello SECRET world\n";
    write_zip(&zip_path, &[("x.txt", payload.as_slice())]).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_uncompressed_bytes_per_entry = 8;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    assert!(out.trim().is_empty(), "expected no findings; got: {out}");

    assert_perf!(
        report.metrics.archive.partial_reasons[PartialReason::EntryOutputBudgetExceeded.as_usize()]
            > 0,
        report.metrics.archive.partial_reasons[PartialReason::EntryOutputBudgetExceeded.as_usize()]
            == 0,
        "expected entry output budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_corrupt_entry_does_not_abort_archive() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("payload.zip");

    write_zip(
        &zip_path,
        &[
            ("bad.txt", b"AAAA".as_slice()),
            ("good.txt", b"SECRET".as_slice()),
        ],
    )
    .unwrap();

    let mut bytes = fs::read(&zip_path).unwrap();
    if bytes.len() >= 4 {
        bytes[0] = 0;
        bytes[1] = 0;
        bytes[2] = 0;
        bytes[3] = 0;
    }
    fs::write(&zip_path, bytes).unwrap();

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    assert!(out.contains("good.txt"), "output: {out}");
    assert_perf!(
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::CorruptEntry.as_usize()] > 0,
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::CorruptEntry.as_usize()] == 0,
        "expected corrupt entry skip to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_long_name_truncates_with_hash() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("payload.zip");

    let long_name = format!("{}file.txt", "a/".repeat(64));
    write_zip(&zip_path, &[(long_name.as_str(), b"SECRET".as_slice())]).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_virtual_path_len_per_entry = 32;
    cfg.archive.max_virtual_path_bytes_per_archive = 1024;

    let (out, _report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    let findings = parse_findings(&out);
    assert!(!findings.is_empty(), "expected findings; output: {out}");
    let path = &findings[0].path;
    assert!(path.contains("~#"), "expected hash suffix in path: {path}");
    assert!(
        path.len() <= 32,
        "expected truncated path length <= 32, got {} ({path})",
        path.len()
    );
}

#[test]
fn zip_encrypted_policy_fail_run_aborts_scan() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("encrypted.zip");
    let plain_path = tmp.path().join("plain.txt");

    let zip_bytes = build_zip_single_stored_entry("secret.txt", b"SECRET", true);
    fs::write(&zip_path, zip_bytes).unwrap();
    fs::write(&plain_path, b"SECRET").unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.encrypted_policy = EncryptedPolicy::FailRun;

    let (out, report) = run_scan(
        vec![file_from_path(&zip_path), file_from_path(&plain_path)],
        cfg,
    );
    assert!(out.trim().is_empty(), "expected no findings; got: {out}");

    let idx = ArchiveSkipReason::EncryptedArchive.as_usize();
    assert_perf!(
        report.metrics.archive.archive_skip_reasons[idx] > 0,
        report.metrics.archive.archive_skip_reasons[idx] == 0,
        "expected encrypted archive skip to be recorded: {:?}",
        report.metrics.archive
    );
}

#[test]
fn archive_entries_use_unique_virtual_file_ids() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("payload.tar");

    let tar_bytes = build_multi_tar(&[("one.txt", b"alpha"), ("two.txt", b"bravo")]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let seen = Arc::new(Mutex::new(Vec::new()));
    let engine = Arc::new(IdEngine {
        seen: Arc::clone(&seen),
    });
    let cfg = cfg_archives_enabled();
    let _report = scan_local(
        engine,
        VecFileSource::new(vec![file_from_path(&tar_path)]),
        cfg,
    );

    let mut ids = seen.lock().unwrap().clone();
    ids.sort_by_key(|id| id.0);
    ids.dedup_by_key(|id| id.0);

    assert_eq!(
        ids.len(),
        2,
        "expected one virtual file id per entry, got {ids:?}"
    );
    assert!(
        ids.iter().all(|id| id.0 & 0x8000_0000 != 0),
        "expected virtual file ids to use high-bit namespace: {ids:?}"
    );
}

#[test]
fn finds_secret_in_tar_with_virtual_path() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("bundle.tar");

    let inner = payload_with_secret_at(5);
    let tar_bytes = build_simple_tar("inner.txt", &inner);
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let f = findings
        .iter()
        .find(|f| f.path.contains("inner.txt"))
        .unwrap();
    assert!(f.path.contains("bundle.tar"));
    assert!(f.path.contains("::inner.txt"));
    assert_locator(&f.path, 't');
    assert_eq!(f.start, 5);
}

#[test]
fn tar_duplicate_names_have_unique_locators() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("dups.tar");

    let a = payload_with_secret_at(1);
    let b = payload_with_secret_at(2);
    let tar_bytes = build_tar(&[("dup.txt", a.as_slice()), ("dup.txt", b.as_slice())]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let dup_paths: Vec<&str> = findings
        .iter()
        .filter(|f| f.path.contains("dup.txt"))
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(
        dup_paths.len(),
        2,
        "expected two findings for duplicate tar names; output: {out}"
    );

    let mut unique = std::collections::HashSet::new();
    for p in &dup_paths {
        assert_locator(p, 't');
        unique.insert(*p);
    }
    assert_eq!(
        unique.len(),
        2,
        "expected unique locators for duplicate tar names; output: {out}"
    );
}

#[test]
fn tar_entry_cap_allows_later_entries() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("caps.tar");

    let big = vec![b'A'; 256];
    let small = payload_with_secret_at(0);
    let tar_bytes = build_tar(&[("big.bin", big.as_slice()), ("small.txt", &small)]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_uncompressed_bytes_per_entry = 32;

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    let findings = parse_findings(&out);

    let hit = findings.iter().find(|f| f.path.contains("small.txt"));
    assert!(
        hit.is_some(),
        "expected finding in later entry; output: {out}"
    );
    assert_locator(&hit.unwrap().path, 't');
    assert_perf!(
        report.metrics.archive.partial_reasons[PartialReason::EntryOutputBudgetExceeded.as_usize()]
            > 0,
        report.metrics.archive.partial_reasons[PartialReason::EntryOutputBudgetExceeded.as_usize()]
            == 0,
        "expected entry output budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn tar_discard_archive_cap_stops_enumeration() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("discard-cap.tar");

    let big = vec![b'A'; 200];
    let later = payload_with_secret_at(0);
    let tar_bytes = build_tar(&[("big.bin", big.as_slice()), ("later.txt", &later)]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_uncompressed_bytes_per_entry = 50;
    cfg.archive.max_total_uncompressed_bytes_per_archive = 100;

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    assert!(
        out.trim().is_empty(),
        "expected no findings after archive cap stop; output: {out}"
    );
    assert_perf!(
        report.metrics.archive.partial_reasons
            [PartialReason::ArchiveOutputBudgetExceeded.as_usize()]
            > 0,
        report.metrics.archive.partial_reasons
            [PartialReason::ArchiveOutputBudgetExceeded.as_usize()]
            == 0,
        "expected archive output budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn tar_nested_gzip_ratio_partial_allows_later_entries() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("ratio.tar");

    let bomb_payload = vec![b'A'; 8192];
    let bomb_gz = build_gz_bytes(&bomb_payload);
    let later = payload_with_secret_at(0);
    let tar_bytes = build_tar(&[("bomb.gz", bomb_gz.as_slice()), ("later.txt", &later)]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_inflation_ratio = 2;

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    let findings = parse_findings(&out);

    let hit = findings.iter().find(|f| f.path.contains("later.txt"));
    assert!(
        hit.is_some(),
        "expected finding in later entry; output: {out}"
    );
    assert_locator(&hit.unwrap().path, 't');
    assert_perf!(
        report.metrics.archive.partial_reasons[PartialReason::InflationRatioExceeded.as_usize()]
            > 0,
        report.metrics.archive.partial_reasons[PartialReason::InflationRatioExceeded.as_usize()]
            == 0,
        "expected inflation ratio partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn tar_nested_gzip_entry_ratio_fires_per_entry() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("entry_ratio.tar");

    // 8 KiB of repeated bytes compresses to ~30 bytes in gzip, giving a
    // ratio well above 2.  The second entry is a normal plaintext file.
    let bomb_payload = vec![b'A'; 8192];
    let bomb_gz = build_gz_bytes(&bomb_payload);
    let later = payload_with_secret_at(0);
    let tar_bytes = build_tar(&[("bomb.gz", bomb_gz.as_slice()), ("later.txt", &later)]);
    fs::write(&tar_path, tar_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_inflation_ratio = 2;

    let (out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);
    let findings = parse_findings(&out);

    // The later entry should still be scanned despite the bomb triggering ratio.
    let hit = findings.iter().find(|f| f.path.contains("later.txt"));
    assert!(
        hit.is_some(),
        "expected finding in later entry; output: {out}"
    );
    assert_locator(&hit.unwrap().path, 't');

    // Verify the entry-level skip reason counter was incremented (not just
    // the archive-level partial reason).
    assert_perf!(
        report.metrics.archive.entry_skip_reasons
            [EntrySkipReason::EntryInflationRatioExceeded.as_usize()]
            > 0,
        report.metrics.archive.entry_skip_reasons
            [EntrySkipReason::EntryInflationRatioExceeded.as_usize()]
            == 0,
        "expected entry inflation ratio skip to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn finds_secret_in_targz_with_virtual_path() {
    let tmp = TempDir::new().unwrap();
    let tgz = tmp.path().join("bundle.tar.gz");

    let inner = payload_with_secret_at(7);
    let tar_bytes = build_simple_tar("deep.txt", &inner);
    let f = File::create(&tgz).unwrap();
    let mut enc = GzEncoder::new(f, Compression::default());
    enc.write_all(&tar_bytes).unwrap();
    enc.finish().unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tgz)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let f = findings
        .iter()
        .find(|f| f.path.contains("deep.txt"))
        .unwrap();
    assert!(f.path.contains("bundle.tar.gz"));
    assert!(f.path.contains("::deep.txt"));
    assert_locator(&f.path, 't');
    assert_eq!(f.start, 7);
}

#[test]
fn finds_secret_in_zip_stored_and_deflated() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("bundle.zip");

    let a = payload_with_secret_at(3);
    let b = payload_with_secret_at(9);

    write_zip_with_methods(
        &zip_path,
        &[
            ("stored.txt", a.as_slice(), CompressionMethod::Stored),
            ("deflated.txt", b.as_slice(), CompressionMethod::Deflated),
        ],
    )
    .unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let stored_hit = findings
        .iter()
        .find(|f| f.path.contains("bundle.zip::stored.txt"));
    let deflated_hit = findings
        .iter()
        .find(|f| f.path.contains("bundle.zip::deflated.txt"));

    assert!(
        stored_hit.is_some(),
        "expected finding in stored entry; output: {out}"
    );
    assert!(
        deflated_hit.is_some(),
        "expected finding in deflated entry; output: {out}"
    );
    assert_locator(&stored_hit.unwrap().path, 'z');
    assert_locator(&deflated_hit.unwrap().path, 'z');
}

#[test]
fn zip_duplicate_names_have_unique_locators() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("dups.zip");

    let a = payload_with_secret_at(1);
    let b = payload_with_secret_at(2);

    // The `zip` crate v2 rejects duplicate filenames, so we build the archive
    // at the byte level using the raw builder which has no such restriction.
    let raw = build_zip_with_specs(&[
        ZipEntrySpec {
            name: "dup.txt",
            data: a.as_slice(),
            flags: 0,
            method: 0, // stored
            extra: &[],
        },
        ZipEntrySpec {
            name: "dup.txt",
            data: b.as_slice(),
            flags: 0,
            method: 0, // stored
            extra: &[],
        },
    ]);
    std::fs::write(&zip_path, &raw).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let dup_paths: Vec<&str> = findings
        .iter()
        .filter(|f| f.path.contains("dup.txt"))
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(
        dup_paths.len(),
        2,
        "expected two findings for duplicate zip names; output: {out}"
    );

    let mut unique = std::collections::HashSet::new();
    for p in &dup_paths {
        assert_locator(p, 'z');
        unique.insert(*p);
    }
    assert_eq!(
        unique.len(),
        2,
        "expected unique locators for duplicate zip names; output: {out}"
    );
}

#[test]
fn zip_long_name_is_scanned_and_truncated() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("longname.zip");

    let payload = payload_with_secret_at(0);
    let long_name = "a".repeat(300);

    write_zip_with_methods(
        &zip_path,
        &[(
            long_name.as_str(),
            payload.as_slice(),
            CompressionMethod::Stored,
        )],
    )
    .unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_virtual_path_len_per_entry = 32;

    let (out, _report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    let findings = parse_findings(&out);

    assert!(!findings.is_empty(), "expected finding; output: {out}");
    let f = &findings[0];
    assert!(
        f.path.contains("~#"),
        "expected hash suffix in path: {}",
        f.path
    );
    assert_locator(&f.path, 'z');
}

#[test]
fn zip_long_name_increments_truncation_counter() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("longname-metrics.zip");

    let payload = payload_with_secret_at(0);
    let long_name = "b".repeat(300);

    write_zip_with_methods(
        &zip_path,
        &[(
            long_name.as_str(),
            payload.as_slice(),
            CompressionMethod::Stored,
        )],
    )
    .unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_virtual_path_len_per_entry = 32;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    assert_perf!(
        report.metrics.archive.paths_truncated > 0,
        report.metrics.archive.paths_truncated == 0,
        "expected truncation counter to increment: {:?}",
        report.metrics.archive
    );
    assert_eq!(
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::MalformedPath.as_usize()],
        0,
        "expected malformed-path counter to remain zero: {:?}",
        report.metrics.archive
    );
    let findings = parse_findings(&out);
    assert!(!findings.is_empty(), "expected finding; output: {out}");
    assert_locator(&findings[0].path, 'z');
}

#[test]
fn zip_corrupt_entry_is_skipped_and_later_entry_scanned() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("corrupt-entry.zip");

    let payload = payload_with_secret_at(0);
    let mut zip_bytes = build_zip_two_entries(("bad.txt", &payload), ("good.txt", &payload));
    let sig = b"PK\x01\x02";
    let cdfh_off = zip_bytes
        .windows(4)
        .position(|w| w == sig)
        .expect("missing CDFH");
    let lfh_off_field = cdfh_off + 42;
    zip_bytes[lfh_off_field..lfh_off_field + 4]
        .copy_from_slice(&u32::MAX.wrapping_sub(1).to_le_bytes());

    fs::write(&zip_path, zip_bytes).unwrap();

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let good_hit = findings.iter().find(|f| f.path.contains("good.txt"));
    assert!(
        good_hit.is_some(),
        "expected finding in later entry; output: {out}"
    );
    assert_locator(&good_hit.unwrap().path, 'z');
    assert_perf!(
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::CorruptEntry.as_usize()] > 0,
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::CorruptEntry.as_usize()] == 0,
        "expected corrupt entry skip to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn zip64_cdfh_sentinel_is_unsupported_feature() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("zip64-cdfh.zip");

    let payload = payload_with_secret_at(0);
    let mut zip_bytes = build_zip_single_stored_entry("only.txt", &payload, false);
    let sig = b"PK\x01\x02";
    let cdfh_off = zip_bytes
        .windows(4)
        .position(|w| w == sig)
        .expect("missing CDFH");
    let sentinel = u32::MAX.to_le_bytes();
    zip_bytes[cdfh_off + 20..cdfh_off + 24].copy_from_slice(&sentinel);
    zip_bytes[cdfh_off + 24..cdfh_off + 28].copy_from_slice(&sentinel);
    zip_bytes[cdfh_off + 42..cdfh_off + 46].copy_from_slice(&sentinel);

    fs::write(&zip_path, zip_bytes).unwrap();

    let (_out, report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    assert_perf!(
        report.metrics.archive.partial_reasons[PartialReason::UnsupportedFeature.as_usize()] > 0,
        report.metrics.archive.partial_reasons[PartialReason::UnsupportedFeature.as_usize()] == 0,
        "expected unsupported feature partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn zip64_eocd_sentinel_is_unsupported_feature() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("zip64-eocd.zip");

    let payload = payload_with_secret_at(0);
    let mut zip_bytes = build_zip_single_stored_entry("only.txt", &payload, false);
    let sig = b"PK\x05\x06";
    let eocd_off = zip_bytes
        .windows(4)
        .position(|w| w == sig)
        .expect("missing EOCD");
    zip_bytes[eocd_off + 10..eocd_off + 12].copy_from_slice(&0xFFFFu16.to_le_bytes());

    fs::write(&zip_path, zip_bytes).unwrap();

    let (_out, report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    assert_perf!(
        report.metrics.archive.archive_skip_reasons
            [ArchiveSkipReason::UnsupportedFeature.as_usize()]
            > 0,
        report.metrics.archive.archive_skip_reasons
            [ArchiveSkipReason::UnsupportedFeature.as_usize()]
            == 0,
        "expected unsupported feature skip to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn encrypted_zip_entry_is_skipped_and_counted() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("encrypted.zip");

    let payload = payload_with_secret_at(0);
    let zip_bytes = build_zip_single_stored_entry("secret.txt", &payload, true);
    fs::write(&zip_path, zip_bytes).unwrap();

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    assert!(out.trim().is_empty(), "expected no findings; got: {out}");

    assert_perf!(
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::EncryptedEntry.as_usize()] > 0,
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::EncryptedEntry.as_usize()] == 0,
        "expected encrypted skip counter to increment: {:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_encrypted_entry_is_skipped_but_plain_entry_scanned() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("encrypted-plain.zip");

    let payload = payload_with_secret_at(0);
    let zip_bytes = build_zip_with_specs(&[
        ZipEntrySpec {
            name: "enc.txt",
            data: b"SECRET",
            flags: 0x0001,
            method: 0,
            extra: b"",
        },
        ZipEntrySpec {
            name: "good.txt",
            data: payload.as_slice(),
            flags: 0x0000,
            method: 0,
            extra: b"",
        },
    ]);
    fs::write(&zip_path, zip_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.encrypted_policy = EncryptedPolicy::SkipWithTelemetry;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    let findings = parse_findings(&out);

    let good_hit = findings.iter().find(|f| f.path.contains("good.txt"));
    assert!(
        good_hit.is_some(),
        "expected finding in plain entry; output: {out}"
    );
    assert_locator(&good_hit.unwrap().path, 'z');
    assert_perf!(
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::EncryptedEntry.as_usize()] > 0,
        report.metrics.archive.entry_skip_reasons[EntrySkipReason::EncryptedEntry.as_usize()] == 0,
        "expected encrypted skip counter to increment: {:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_encrypted_policy_fail_archive_stops_scanning() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("encrypted-fail.zip");

    let payload = payload_with_secret_at(0);
    let zip_bytes = build_zip_with_specs(&[
        ZipEntrySpec {
            name: "enc.txt",
            data: b"SECRET",
            flags: 0x0001,
            method: 0,
            extra: b"",
        },
        ZipEntrySpec {
            name: "good.txt",
            data: payload.as_slice(),
            flags: 0x0000,
            method: 0,
            extra: b"",
        },
    ]);
    fs::write(&zip_path, zip_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.encrypted_policy = EncryptedPolicy::FailArchive;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    assert!(out.trim().is_empty(), "expected no findings; output: {out}");
    assert_perf!(
        report.metrics.archive.archive_skip_reasons[ArchiveSkipReason::EncryptedArchive.as_usize()]
            > 0,
        report.metrics.archive.archive_skip_reasons[ArchiveSkipReason::EncryptedArchive.as_usize()]
            == 0,
        "expected encrypted archive skip to be recorded: {:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_unsupported_compression_is_skipped_and_plain_entry_scanned() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("unsupported.zip");

    let payload = payload_with_secret_at(0);
    let zip_bytes = build_zip_with_specs(&[
        ZipEntrySpec {
            name: "bad.bin",
            data: b"NOPE",
            flags: 0x0000,
            method: 99,
            extra: b"",
        },
        ZipEntrySpec {
            name: "good.txt",
            data: payload.as_slice(),
            flags: 0x0000,
            method: 0,
            extra: b"",
        },
    ]);
    fs::write(&zip_path, zip_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.unsupported_policy = UnsupportedPolicy::SkipWithTelemetry;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    let findings = parse_findings(&out);
    let good_hit = findings.iter().find(|f| f.path.contains("good.txt"));
    assert!(
        good_hit.is_some(),
        "expected finding in plain entry; output: {out}"
    );
    assert_locator(&good_hit.unwrap().path, 'z');
    assert_perf!(
        report.metrics.archive.entry_skip_reasons
            [EntrySkipReason::UnsupportedCompression.as_usize()]
            > 0,
        report.metrics.archive.entry_skip_reasons
            [EntrySkipReason::UnsupportedCompression.as_usize()]
            == 0,
        "expected unsupported compression skip to be recorded: {:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_extra_field_hits_metadata_budget() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("extra-budget.zip");

    let payload = payload_with_secret_at(0);
    let extra = vec![b'X'; 128];
    let zip_bytes = build_zip_with_specs(&[ZipEntrySpec {
        name: "extra.txt",
        data: payload.as_slice(),
        flags: 0x0000,
        method: 0,
        extra: extra.as_slice(),
    }]);
    fs::write(&zip_path, zip_bytes).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_archive_metadata_bytes = 64;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    assert!(out.trim().is_empty(), "expected no findings; output: {out}");
    assert_perf!(
        report.metrics.archive.partial_reasons[PartialReason::MetadataBudgetExceeded.as_usize()]
            > 0,
        report.metrics.archive.partial_reasons[PartialReason::MetadataBudgetExceeded.as_usize()]
            == 0,
        "expected metadata budget partial to be recorded; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_traversal_names_are_sanitized_in_virtual_paths() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("traversal.zip");

    let payload = payload_with_secret_at(0);

    let f = File::create(&zip_path).unwrap();
    let mut w = zip::ZipWriter::new(f);
    let opt = FileOptions::<()>::default().compression_method(CompressionMethod::Stored);
    w.start_file("../evil.txt", opt).unwrap();
    w.write_all(&payload).unwrap();
    w.finish().unwrap();

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let f = findings
        .iter()
        .find(|f| f.path.contains("traversal.zip::"))
        .unwrap();
    assert!(
        !f.path.contains(".."),
        "virtual path contains traversal: {:?}",
        f.path
    );
    assert_locator(&f.path, 'z');
    assert_perf!(
        report.metrics.archive.paths_had_traversal > 0,
        report.metrics.archive.paths_had_traversal == 0,
        "expected traversal counter to increment: {:?}",
        report.metrics.archive
    );
}

#[test]
fn tar_pax_path_override_is_used() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("pax.tar");

    let payload = payload_with_secret_at(0);
    let pax_path = "override/path/secret.txt";
    let tar_bytes = build_tar_with_pax_path(pax_path, &payload);
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let f = findings.iter().find(|f| f.path.contains(pax_path)).unwrap();
    assert_locator(&f.path, 't');
    assert!(!f.path.contains("ignored.txt"));
}

#[test]
fn tar_gnu_longname_is_used() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("gnu-long.tar");

    let payload = payload_with_secret_at(0);
    let long_name = format!("long/{}_name.txt", "a".repeat(120));
    let tar_bytes = build_tar_with_gnu_longname(&long_name, &payload);
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let f = findings
        .iter()
        .find(|f| f.path.contains(&long_name))
        .unwrap();
    assert_locator(&f.path, 't');
    assert!(!f.path.contains("ignored.txt"));
}

#[test]
fn zip_component_cap_exceeded_is_reported_and_scanned() {
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("component-cap.zip");

    let payload = payload_with_secret_at(0);
    let mut name = String::new();
    for i in 0..300 {
        if i != 0 {
            name.push('/');
        }
        name.push('a');
    }

    write_zip_with_methods(
        &zip_path,
        &[(name.as_str(), payload.as_slice(), CompressionMethod::Stored)],
    )
    .unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_virtual_path_len_per_entry = 512;

    let (out, report) = run_scan(vec![file_from_path(&zip_path)], cfg);
    let findings = parse_findings(&out);

    assert!(!findings.is_empty(), "expected finding; output: {out}");
    let f = &findings[0];
    assert!(
        f.path.contains("<component-cap-exceeded>"),
        "expected component-cap placeholder in path: {}",
        f.path
    );
    assert_locator(&f.path, 'z');
    assert_perf!(
        report.metrics.archive.paths_component_cap_exceeded > 0,
        report.metrics.archive.paths_component_cap_exceeded == 0,
        "expected component cap counter to increment: {:?}",
        report.metrics.archive
    );
}

#[test]
fn archives_disabled_does_not_change_plain_file_results() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.path().join("plain.txt");
    fs::write(&plain, payload_with_secret_at(0)).unwrap();

    let mut cfg_disabled = LocalConfig::default();
    cfg_disabled.archive.enabled = false;
    cfg_disabled.chunk_size = 64;

    let (out_disabled, _r0) = run_scan(vec![file_from_path(&plain)], cfg_disabled);

    let mut cfg_enabled = cfg_archives_enabled();
    cfg_enabled.archive.enabled = true;

    let (out_enabled, _r1) = run_scan(vec![file_from_path(&plain)], cfg_enabled);

    assert_eq!(out_disabled, out_enabled);
}

#[test]
fn finds_secret_in_nested_tar_inside_tar() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("outer.tar");

    let inner_payload = payload_with_secret_at(6);
    let inner_tar_bytes = build_simple_tar("deep.txt", &inner_payload);
    let tar_bytes = build_simple_tar("inner.tar", &inner_tar_bytes);
    fs::write(&tar_path, tar_bytes).unwrap();

    let (out, _report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    let f = findings
        .iter()
        .find(|f| f.path.contains("deep.txt"))
        .unwrap();
    assert!(f.path.contains("outer.tar::inner.tar"));
    assert!(f.path.contains("::deep.txt"));
    assert_locator(&f.path, 't');
}

#[test]
fn nested_container_entry_is_counted_as_scanned() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("outer.tar");

    let inner_payload = payload_with_secret_at(2);
    let inner_tar_bytes = build_simple_tar("deep.txt", &inner_payload);
    let outer_tar_bytes = build_simple_tar("inner.tar", &inner_tar_bytes);
    fs::write(&tar_path, outer_tar_bytes).unwrap();

    let (_out, report) = run_scan(vec![file_from_path(&tar_path)], cfg_archives_enabled());

    assert_perf!(
        report.metrics.archive.entries_scanned >= 2,
        report.metrics.archive.entries_scanned == 0,
        "expected container entry to be counted; metrics={:?}",
        report.metrics.archive
    );
}

#[test]
fn nested_depth_limit_is_recorded() {
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("outer.tar");

    let inner_payload = payload_with_secret_at(3);
    let inner_tar = build_simple_tar("deep.txt", &inner_payload);
    let inner_targz = build_gz_bytes(&inner_tar);
    let outer_tar = build_simple_tar("inner.tar.gz", &inner_targz);
    fs::write(&tar_path, outer_tar).unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.max_archive_depth = 1;

    let (_out, report) = run_scan(vec![file_from_path(&tar_path)], cfg);

    let idx = ArchiveSkipReason::DepthExceeded.as_usize();
    assert_perf!(
        report.metrics.archive.archive_skip_reasons[idx] > 0,
        report.metrics.archive.archive_skip_reasons[idx] == 0,
        "expected depth_exceeded to be counted: {:?}",
        report.metrics.archive
    );
}

// ============================================================================
// Archive + persistence integration tests
// ============================================================================

/// Helper: run a scan with an InMemoryStoreProducer and return (output, report, producer).
fn run_scan_with_persistence(
    files: Vec<LocalFile>,
    mut cfg: LocalConfig,
) -> (String, LocalReport, Arc<InMemoryStoreProducer>) {
    let engine = Arc::new(MockEngine::new(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        16,
    ));
    let sink = Arc::new(VecEventOutput::new());
    let producer = Arc::new(InMemoryStoreProducer::default());
    cfg.event_sink = Arc::clone(&sink) as Arc<dyn EventOutput>;
    cfg.store_producer = Some(Arc::clone(&producer) as Arc<dyn StoreProducer>);
    let report = scan_local(engine, VecFileSource::new(files), cfg);
    let out = String::from_utf8_lossy(&sink.take()).to_string();
    (out, report, producer)
}

#[test]
fn persistence_batches_emitted_for_gzip_scan() {
    let dir = TempDir::new().unwrap();
    let gz = dir.path().join("payload.gz");
    let payload = payload_with_secret_at(5);
    write_gz(&gz, &payload).unwrap();

    let cfg = cfg_archives_enabled();
    let (_out, report, producer) = run_scan_with_persistence(vec![file_from_path(&gz)], cfg);

    let batches = producer.batches();
    let persisted: usize = batches.iter().map(|b| b.findings.len()).sum();
    assert!(
        !batches.is_empty(),
        "expected persistence batches for gzip scan"
    );
    assert_eq!(
        persisted as u64, report.metrics.findings_emitted,
        "persisted count should match findings_emitted"
    );

    // Run-loss should be recorded.
    let losses = producer.losses();
    assert_eq!(losses.len(), 1, "expected exactly one run-loss record");
}

#[test]
fn persistence_batches_emitted_for_tar_scan() {
    let dir = TempDir::new().unwrap();
    let tar_path = dir.path().join("payload.tar");
    let payload = payload_with_secret_at(3);
    let tar_bytes = build_simple_tar("entry.txt", &payload);
    fs::write(&tar_path, tar_bytes).unwrap();

    let cfg = cfg_archives_enabled();
    let (_out, report, producer) = run_scan_with_persistence(vec![file_from_path(&tar_path)], cfg);

    let batches = producer.batches();
    let persisted: usize = batches.iter().map(|b| b.findings.len()).sum();
    assert!(
        !batches.is_empty(),
        "expected persistence batches for tar scan"
    );
    assert_eq!(
        persisted as u64, report.metrics.findings_emitted,
        "persisted count should match findings_emitted"
    );

    let losses = producer.losses();
    assert_eq!(losses.len(), 1, "expected exactly one run-loss record");
}

#[test]
fn persistence_batches_emitted_for_zip_scan() {
    let dir = TempDir::new().unwrap();
    let zip_path = dir.path().join("payload.zip");
    let payload = payload_with_secret_at(2);
    write_zip(&zip_path, &[("secret.txt", &payload)]).unwrap();

    let cfg = cfg_archives_enabled();
    let (_out, report, producer) = run_scan_with_persistence(vec![file_from_path(&zip_path)], cfg);

    let batches = producer.batches();
    let persisted: usize = batches.iter().map(|b| b.findings.len()).sum();
    assert!(
        !batches.is_empty(),
        "expected persistence batches for zip scan"
    );
    assert_eq!(
        persisted as u64, report.metrics.findings_emitted,
        "persisted count should match findings_emitted"
    );

    let losses = producer.losses();
    assert_eq!(losses.len(), 1, "expected exactly one run-loss record");
}

// ============================================================================
// Sniff-based archive detection tests (no archive extension)
// ============================================================================

/// File with no archive extension but valid gzip magic should be detected via
/// header sniffing and produce findings from archive expansion.
#[test]
fn sniff_detected_gzip_archive_emits_findings() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("data.xyz"); // no .gz extension

    let payload = payload_with_secret_at(5);
    let gz_bytes = build_gz_bytes(&payload);
    fs::write(&path, gz_bytes).unwrap();

    let (out, report) = run_scan(vec![file_from_path(&path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    assert!(
        !findings.is_empty(),
        "expected finding from sniff-detected gzip; output: {out}"
    );
    assert!(
        findings[0].path.contains("data.xyz"),
        "finding path should reference the original file: {}",
        findings[0].path
    );
    assert_perf!(
        report.metrics.archive.archives_seen > 0,
        report.metrics.archive.archives_seen == 0,
        "expected archives_seen > 0 for sniff-detected gzip; metrics={:?}",
        report.metrics.archive
    );
}

/// File with no archive extension but valid tar ustar header (>= 512 bytes)
/// should be detected via header sniffing and produce findings.
///
/// Tar ustar detection requires 512 bytes in the first read so
/// `chunk_size` must be >= `TAR_BLOCK_LEN`.
#[test]
fn sniff_detected_tar_archive_emits_findings() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("payload.xyz"); // no .tar extension

    let tar_bytes = build_simple_tar("inner.txt", b"prefix SECRET suffix");
    // Tar archive is always >= 512 bytes due to the header block.
    assert!(
        tar_bytes.len() >= TAR_BLOCK_LEN,
        "tar must be >= 512 bytes for ustar detection"
    );
    fs::write(&path, tar_bytes).unwrap();

    // Tar ustar magic lives at offset 257, so the first read must be
    // >= 512 bytes for sniff_kind_from_header to detect it.
    let mut cfg = cfg_archives_enabled();
    cfg.chunk_size = 1024; // ensure first read covers the full tar header

    let (out, report) = run_scan(vec![file_from_path(&path)], cfg);
    let findings = parse_findings(&out);

    assert!(
        !findings.is_empty(),
        "expected finding from sniff-detected tar; output: {out}"
    );
    assert!(
        findings[0].path.contains("inner.txt"),
        "finding path should reference the tar entry: {}",
        findings[0].path
    );
    assert_perf!(
        report.metrics.archive.archives_seen > 0,
        report.metrics.archive.archives_seen == 0,
        "expected archives_seen > 0 for sniff-detected tar; metrics={:?}",
        report.metrics.archive
    );
}

/// File with no archive extension but valid ZIP magic (PK\x03\x04) should be
/// detected via header sniffing and produce findings.
#[test]
fn sniff_detected_zip_archive_emits_findings() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("bundle.xyz"); // no .zip extension

    let payload = payload_with_secret_at(2);
    let zip_bytes = build_zip_single_stored_entry("secret.txt", &payload, false);
    fs::write(&path, zip_bytes).unwrap();

    let (out, report) = run_scan(vec![file_from_path(&path)], cfg_archives_enabled());
    let findings = parse_findings(&out);

    assert!(
        !findings.is_empty(),
        "expected finding from sniff-detected zip; output: {out}"
    );
    assert!(
        findings[0].path.contains("secret.txt"),
        "finding path should reference the zip entry: {}",
        findings[0].path
    );
    assert_locator(&findings[0].path, 'z');
    assert_perf!(
        report.metrics.archive.archives_seen > 0,
        report.metrics.archive.archives_seen == 0,
        "expected archives_seen > 0 for sniff-detected zip; metrics={:?}",
        report.metrics.archive
    );
}

// ── Gap 8: FailRun policy propagation for unsupported_policy ───────

#[test]
fn tar_with_nested_zip_fail_run_aborts_scan() {
    // A zip entry inside a tar can't be recursed (no random access).
    // With unsupported_policy=FailRun, the entire run should be aborted
    // and the plain file should NOT be scanned.
    let tmp = TempDir::new().unwrap();
    let tar_path = tmp.path().join("nested.tar");
    let plain_path = tmp.path().join("plain.txt");

    // Build a zip file to embed inside the tar.
    let zip_bytes = build_zip_single_stored_entry("inner.txt", b"ZIP_CONTENT", false);
    let tar_bytes = build_simple_tar_bytes(b"inner.zip", &zip_bytes);
    fs::write(&tar_path, tar_bytes).unwrap();
    fs::write(&plain_path, b"SECRET").unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.unsupported_policy = UnsupportedPolicy::FailRun;

    let (out, report) = run_scan(
        vec![file_from_path(&tar_path), file_from_path(&plain_path)],
        cfg,
    );

    // FailRun should abort the entire run: no findings from the plain file.
    assert!(
        out.trim().is_empty(),
        "expected no findings with FailRun; got: {out}"
    );

    let idx = ArchiveSkipReason::NeedsRandomAccessNoSpill.as_usize();
    assert_perf!(
        report.metrics.archive.archive_skip_reasons[idx] > 0,
        report.metrics.archive.archive_skip_reasons[idx] == 0,
        "expected NeedsRandomAccessNoSpill skip reason: {:?}",
        report.metrics.archive
    );
}

#[test]
fn zip_unsupported_compression_fail_run_aborts_scan() {
    // A zip entry with an unsupported compression method + FailRun should abort.
    let tmp = TempDir::new().unwrap();
    let zip_path = tmp.path().join("unsupported.zip");
    let plain_path = tmp.path().join("plain.txt");

    let zip_bytes = build_zip_unsupported_compression("entry.txt", b"PAYLOAD");
    fs::write(&zip_path, zip_bytes).unwrap();
    fs::write(&plain_path, b"SECRET").unwrap();

    let mut cfg = cfg_archives_enabled();
    cfg.archive.unsupported_policy = UnsupportedPolicy::FailRun;

    let (out, _report) = run_scan(
        vec![file_from_path(&zip_path), file_from_path(&plain_path)],
        cfg,
    );

    assert!(
        out.trim().is_empty(),
        "expected no findings with FailRun on unsupported compression; got: {out}"
    );
}

/// Build a single-entry tar from raw name bytes and payload.
fn build_simple_tar_bytes(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let name_str = std::str::from_utf8(name).unwrap_or("entry");
    build_simple_tar(name_str, payload)
}

/// Build a zip file with a single entry using compression method 99 (unsupported).
fn build_zip_unsupported_compression(name: &str, payload: &[u8]) -> Vec<u8> {
    // We'll build a minimal zip by hand with method=99 (WinZip AES).
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let payload_len = payload.len() as u32;

    // Local file header.
    let mut lfh = Vec::new();
    lfh.extend_from_slice(&0x04034b50u32.to_le_bytes()); // LFH signature
    lfh.extend_from_slice(&20u16.to_le_bytes()); // version needed
    lfh.extend_from_slice(&0u16.to_le_bytes()); // flags
    lfh.extend_from_slice(&99u16.to_le_bytes()); // compression method (unsupported)
    lfh.extend_from_slice(&0u16.to_le_bytes()); // mod time
    lfh.extend_from_slice(&0u16.to_le_bytes()); // mod date
    lfh.extend_from_slice(&0u32.to_le_bytes()); // crc32
    lfh.extend_from_slice(&payload_len.to_le_bytes()); // compressed size
    lfh.extend_from_slice(&payload_len.to_le_bytes()); // uncompressed size
    lfh.extend_from_slice(&name_len.to_le_bytes()); // name length
    lfh.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    lfh.extend_from_slice(name_bytes);
    let lfh_offset = 0u32;

    // File data.
    let mut out = lfh;
    out.extend_from_slice(payload);

    // Central directory file header.
    let cdfh_offset = out.len() as u32;
    let mut cdfh = Vec::new();
    cdfh.extend_from_slice(&0x02014b50u32.to_le_bytes()); // CDFH signature
    cdfh.extend_from_slice(&20u16.to_le_bytes()); // version made by
    cdfh.extend_from_slice(&20u16.to_le_bytes()); // version needed
    cdfh.extend_from_slice(&0u16.to_le_bytes()); // flags
    cdfh.extend_from_slice(&99u16.to_le_bytes()); // compression method
    cdfh.extend_from_slice(&0u16.to_le_bytes()); // mod time
    cdfh.extend_from_slice(&0u16.to_le_bytes()); // mod date
    cdfh.extend_from_slice(&0u32.to_le_bytes()); // crc32
    cdfh.extend_from_slice(&payload_len.to_le_bytes()); // compressed size
    cdfh.extend_from_slice(&payload_len.to_le_bytes()); // uncompressed size
    cdfh.extend_from_slice(&name_len.to_le_bytes()); // name length
    cdfh.extend_from_slice(&0u16.to_le_bytes()); // extra field length
    cdfh.extend_from_slice(&0u16.to_le_bytes()); // comment length
    cdfh.extend_from_slice(&0u16.to_le_bytes()); // disk number start
    cdfh.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    cdfh.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    cdfh.extend_from_slice(&lfh_offset.to_le_bytes()); // relative offset of LFH
    cdfh.extend_from_slice(name_bytes);
    out.extend_from_slice(&cdfh);

    // End of central directory record.
    let eocd_offset = out.len();
    let cd_size = (eocd_offset as u32) - cdfh_offset;
    let mut eocd = Vec::new();
    eocd.extend_from_slice(&0x06054b50u32.to_le_bytes()); // EOCD signature
    eocd.extend_from_slice(&0u16.to_le_bytes()); // disk number
    eocd.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    eocd.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
    eocd.extend_from_slice(&1u16.to_le_bytes()); // total entries
    eocd.extend_from_slice(&cd_size.to_le_bytes()); // CD size
    eocd.extend_from_slice(&cdfh_offset.to_le_bytes()); // CD offset
    eocd.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out.extend_from_slice(&eocd);

    out
}
