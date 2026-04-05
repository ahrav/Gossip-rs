use super::super::engine_stub::{EngineTuning, FindingRec, MockEngine, MockRule, RuleId};
use super::super::engine_trait::{EngineScratch, FindingRecord, FindingWithHash, ScanEngine};
use super::super::{TsBufferPool, TsBufferPoolConfig};
use super::*;
use crate::api::FileId;
use crate::events::VecEventOutput;
use tempfile::tempdir;

struct DuplicateDropEngine;

struct DuplicateDropScratch {
    findings: Vec<FindingWithHash<FindingRec>>,
    dropped_findings: u64,
}

impl EngineScratch for DuplicateDropScratch {
    type Finding = FindingWithHash<FindingRec>;

    fn clear(&mut self) {
        self.findings.clear();
        self.dropped_findings = 0;
    }

    fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        self.findings
            .retain(|f| f.root_hint_end() >= new_bytes_start);
    }

    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
        out.append(&mut self.findings);
    }

    fn pending_findings_len(&self) -> usize {
        self.findings.len()
    }

    fn dropped_findings(&self) -> u64 {
        self.dropped_findings
    }
}

impl ScanEngine for DuplicateDropEngine {
    type Scratch = DuplicateDropScratch;

    fn required_overlap(&self) -> usize {
        0
    }

    fn new_scratch(&self) -> Self::Scratch {
        DuplicateDropScratch {
            findings: Vec::with_capacity(8),
            dropped_findings: 0,
        }
    }

    fn scan_chunk_into(
        &self,
        data: &[u8],
        _file_id: FileId,
        _base_offset: u64,
        scratch: &mut Self::Scratch,
    ) {
        if data.is_empty() {
            return;
        }
        let rec = FindingRec {
            rule_id: RuleId(0),
            blob_offset_start: 0,
            blob_offset_end: 6,
            window_start: 0,
            window_end: 6,
            confidence_score: 0,
        };
        // Emit duplicates so scheduler dedupe prunes one finding.
        scratch.findings.push(FindingWithHash::new(rec, [0; 32]));
        scratch.findings.push(FindingWithHash::new(rec, [0; 32]));
        // Simulate engine-side cap drops for parity accounting checks.
        scratch.dropped_findings = scratch.dropped_findings.saturating_add(2);
    }

    fn rule_name(&self, _rule_id: u32) -> &str {
        "dup"
    }

    fn rule_fingerprint_bytes(&self, _rule_id: u32) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("gossip/rule/v1");
        h.update(b"dup");
        *h.finalize().as_bytes()
    }

    fn max_findings_per_chunk(&self) -> usize {
        8
    }
}

struct DistinctHashEngine;

struct DistinctHashScratch {
    findings: Vec<FindingWithHash<FindingRec>>,
}

impl EngineScratch for DistinctHashScratch {
    type Finding = FindingWithHash<FindingRec>;

    fn clear(&mut self) {
        self.findings.clear();
    }

    fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        self.findings
            .retain(|f| f.root_hint_end() >= new_bytes_start);
    }

    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
        out.append(&mut self.findings);
    }

    fn pending_findings_len(&self) -> usize {
        self.findings.len()
    }
}

impl ScanEngine for DistinctHashEngine {
    type Scratch = DistinctHashScratch;

    fn required_overlap(&self) -> usize {
        0
    }

    fn new_scratch(&self) -> Self::Scratch {
        DistinctHashScratch {
            findings: Vec::with_capacity(8),
        }
    }

    fn scan_chunk_into(
        &self,
        data: &[u8],
        _file_id: FileId,
        _base_offset: u64,
        scratch: &mut Self::Scratch,
    ) {
        scratch.clear();
        if data.is_empty() {
            return;
        }

        let rec = FindingRec {
            rule_id: RuleId(0),
            blob_offset_start: 0,
            blob_offset_end: 6,
            window_start: 0,
            window_end: 6,
            confidence_score: 0,
        };
        scratch.findings.push(FindingWithHash::new(rec, [0xA1; 32]));
        scratch.findings.push(FindingWithHash::new(rec, [0xB2; 32]));
    }

    fn rule_name(&self, _rule_id: u32) -> &str {
        "distinct-hash"
    }

    fn rule_fingerprint_bytes(&self, _rule_id: u32) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("gossip/rule/v1");
        h.update(b"distinct-hash");
        *h.finalize().as_bytes()
    }

    fn max_findings_per_chunk(&self) -> usize {
        8
    }
}

#[test]
fn uring_finds_boundary_spanning_match() -> io::Result<()> {
    // Create a mock engine that looks for "SECRET"
    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6, // overlap = pattern length to catch boundary spans
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    let file_path = dir.path().join("a.txt");

    // Force boundary for chunk_size=8.
    // Content: "xxxxSECRETyyyyyy" (16 bytes)
    // With chunk_size=8, first chunk = [0..8), second = [8..16)
    // "SECRET" spans bytes 4-10, crossing the boundary at 8.
    let content = b"xxxxSECRETyyyyyy";
    std::fs::write(&file_path, content)?;

    let sink = Arc::new(VecEventOutput::new());

    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 8,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig::default(),
    };

    let (_summary, _io_stats, _cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink.clone())?;

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("secret"),
        "expected output to contain rule name 'secret', got: {}",
        out_str
    );

    Ok(())
}

#[test]
fn global_only_pool_works() {
    // Verify minimal pool (single worker, minimal local queue) works.
    let pool = TsBufferPool::new(TsBufferPoolConfig {
        buffer_len: 1024,
        total_buffers: 8,
        workers: 1,
        local_queue_cap: 1,
    });

    // Acquire and release a buffer to verify basic functionality
    let buf = pool.try_acquire();
    assert!(buf.is_some());

    drop(buf);

    // Verify we can acquire again after release
    let buf2 = pool.try_acquire();
    assert!(buf2.is_some());
}

#[test]
fn uring_open_stat_parity_with_blocking() -> io::Result<()> {
    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    let file_path = dir.path().join("a.txt");
    std::fs::write(&file_path, b"xxSECRETyy")?;

    let base_cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 16,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig::default(),
    };

    let sink_blocking = Arc::new(VecEventOutput::new());
    let (_summary, _io_stats, _cpu_metrics) = scan_local_fs_uring(
        Arc::clone(&engine),
        &[dir.path().to_path_buf()],
        base_cfg.clone(),
        sink_blocking.clone(),
    )?;
    let out_blocking = sink_blocking.take();

    let sink_uring = Arc::new(VecEventOutput::new());
    let mut uring_cfg = base_cfg;
    uring_cfg.open_stat_mode = OpenStatMode::UringPreferred;
    let (_summary, _io_stats, _cpu_metrics) = scan_local_fs_uring(
        Arc::clone(&engine),
        &[dir.path().to_path_buf()],
        uring_cfg,
        sink_uring.clone(),
    )?;
    let out_uring = sink_uring.take();

    assert_eq!(
        out_blocking, out_uring,
        "open/stat path should match blocking output"
    );

    Ok(())
}

#[test]
fn blocking_mode_skips_open_stat_ops() -> io::Result<()> {
    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    let file_path = dir.path().join("a.txt");
    std::fs::write(&file_path, b"xxSECRETyy")?;

    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 16,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig::default(),
    };

    let sink = Arc::new(VecEventOutput::new());
    let (_summary, io_stats, _cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink)?;

    assert_eq!(io_stats.open_ops_submitted, 0);
    assert_eq!(io_stats.stat_ops_submitted, 0);
    assert_eq!(io_stats.open_stat_fallbacks, 0);

    Ok(())
}

#[test]
fn uring_binary_skipped_counted() -> io::Result<()> {
    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    // File contains NUL bytes so it looks binary.
    let file_path = dir.path().join("binary.dat");
    std::fs::write(&file_path, b"\x00\x01\x02SECRET")?;

    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 64,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: true,
        archive: ArchiveConfig {
            enabled: false,
            ..ArchiveConfig::default()
        },
    };

    let sink = Arc::new(VecEventOutput::new());
    let (_summary, io_stats, cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink.clone())?;

    assert_eq!(
        io_stats.binary_skipped, 1,
        "io_stats should count the binary file as skipped"
    );
    assert_eq!(
        cpu_metrics.binary_skipped, 1,
        "cpu_metrics should count the binary file as skipped"
    );
    // The file should NOT have been scanned (no findings for "SECRET").
    let events = sink.take();
    assert!(events.is_empty(), "binary file should not produce findings");

    Ok(())
}

#[test]
fn uring_extract_path_counts_dropped_findings() -> io::Result<()> {
    let engine = Arc::new(DuplicateDropEngine);
    let dir = tempdir()?;
    let file_path = dir.path().join("notebook.ipynb");
    std::fs::write(
        &file_path,
        br#"{"cells":[{"cell_type":"code","source":["SECRET\n"]}],"metadata":{},"nbformat":4,"nbformat_minor":5}"#,
    )?;

    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 64,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: true,
        archive: ArchiveConfig {
            enabled: false,
            ..ArchiveConfig::default()
        },
    };

    let sink = Arc::new(VecEventOutput::new());
    let (_summary, _io_stats, cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink)?;

    assert_eq!(cpu_metrics.binary_extracted, 1);
    assert_eq!(
        cpu_metrics.findings_dropped, 1,
        "extraction path should count effective dropped findings (engine drops minus scheduler prunes)"
    );

    Ok(())
}

#[test]
fn uring_cross_rule_mode_uses_hash_aware_winner_pass() -> io::Result<()> {
    let engine = Arc::new(DistinctHashEngine);
    let dir = tempdir()?;
    let file_path = dir.path().join("a.txt");
    std::fs::write(&file_path, b"SECRET")?;

    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 64,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig {
            enabled: false,
            ..ArchiveConfig::default()
        },
    };

    let sink = Arc::new(VecEventOutput::new());
    let (_summary, _io_stats, metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink)?;
    assert_eq!(
        metrics.findings_emitted, 2,
        "distinct hashes must preserve both findings"
    );

    Ok(())
}

#[test]
fn extract_worker_uses_existing_fd_after_unlink() -> io::Result<()> {
    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    let file_path = dir.path().join("gone.ipynb");
    std::fs::write(
        &file_path,
        br#"{"cells":[{"cell_type":"code","source":["SECRET\n"]}],"metadata":{},"nbformat":4,"nbformat_minor":5}"#,
    )?;

    let file = File::open(&file_path)?;
    let file_size = file.metadata()?.len();
    std::fs::remove_file(&file_path)?;

    let budget = Arc::new(CountBudget::new(1));
    let token = Arc::new(FileToken {
        _permit: budget.acquire(1),
        file_id: FileId(1),
        display: b"gone.ipynb".to_vec().into_boxed_slice().into(),
    });

    let (tx, rx) = chan::bounded::<ExtractWork>(1);
    tx.send(ExtractWork {
        file,
        file_size,
        fmt: crate::content_policy::ExtractableFormat::Ipynb,
        token,
    })
    .map_err(|_| io::Error::other("failed to enqueue extraction work"))?;
    drop(tx);

    let sink = Arc::new(VecEventOutput::new());
    let stats = extract_worker_loop(rx, engine, sink.clone());

    assert_eq!(stats.files_extracted, 1, "expected extraction from open fd");
    assert_eq!(stats.io_errors, 0);
    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("secret"),
        "expected finding after unlink; output: {out_str}"
    );

    Ok(())
}

#[test]
fn uring_archive_sniffed_counted() -> io::Result<()> {
    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    // File with no archive extension but gzip magic bytes in content.
    let file_path = dir.path().join("data.bin");
    let mut content = vec![0x1f, 0x8b, 0x08, 0x00];
    content.extend_from_slice(&[0u8; 60]); // padding to make a valid-ish file
    std::fs::write(&file_path, &content)?;

    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 64,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig::default(), // enabled=true by default
    };

    let sink = Arc::new(VecEventOutput::new());
    let (_summary, io_stats, _cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink)?;

    assert_eq!(
        io_stats.archives_sniffed, 1,
        "io_stats should count the file as archive-sniffed"
    );

    Ok(())
}

/// Sniff-detected gzip archive should emit actual findings, not just
/// increment a counter. This tests the full chain: I/O thread sniff ->
/// archive channel send -> archive_worker_loop -> scan_gzip_stream ->
/// finding emission.
#[test]
fn uring_sniff_detected_gzip_emits_findings() -> io::Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    // No archive extension — must be discovered via magic byte sniffing.
    let file_path = dir.path().join("mystery.dat");
    let payload = b"prefix SECRET suffix";
    let mut gz_bytes = Vec::new();
    {
        let mut enc = GzEncoder::new(&mut gz_bytes, Compression::default());
        std::io::Write::write_all(&mut enc, payload).unwrap();
        enc.finish().unwrap();
    }
    std::fs::write(&file_path, &gz_bytes)?;

    let sink = Arc::new(VecEventOutput::new());
    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 64,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig::default(), // enabled=true
    };

    let (_summary, io_stats, _cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink.clone())?;

    assert!(
        io_stats.archives_sniffed >= 1,
        "expected archives_sniffed >= 1, got {}",
        io_stats.archives_sniffed
    );

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("secret"),
        "expected finding from sniff-detected gzip archive; output: {out_str}"
    );

    Ok(())
}

/// Extension-routed archive from discovery should emit actual findings.
/// Files with recognized archive extensions bypass I/O threads entirely
/// and go directly to archive workers.
#[test]
fn uring_extension_routed_archive_emits_findings() -> io::Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    // Recognized archive extension — routed at discovery time.
    let file_path = dir.path().join("secret.gz");
    let payload = b"padding SECRET padding";
    let mut gz_bytes = Vec::new();
    {
        let mut enc = GzEncoder::new(&mut gz_bytes, Compression::default());
        std::io::Write::write_all(&mut enc, payload).unwrap();
        enc.finish().unwrap();
    }
    std::fs::write(&file_path, &gz_bytes)?;

    let sink = Arc::new(VecEventOutput::new());
    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 64,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig::default(), // enabled=true
    };

    let (summary, _io_stats, _cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink.clone())?;

    assert!(
        summary.archives_routed >= 1,
        "expected archives_routed >= 1, got {}",
        summary.archives_routed
    );

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("secret"),
        "expected finding from extension-routed archive; output: {out_str}"
    );

    Ok(())
}

/// Sniff-detected ZIP archive (no .zip extension) should produce findings
/// through the archive worker chain via I/O thread sniffing.
#[test]
fn uring_sniff_detected_zip_emits_findings() -> io::Result<()> {
    let engine = Arc::new(MockEngine::with_tuning(
        vec![MockRule {
            name: "secret".into(),
            pattern: b"SECRET".to_vec(),
        }],
        6,
        EngineTuning {
            max_findings_per_chunk: 128,
            max_rules: 16,
        },
    ));

    let dir = tempdir()?;
    // No .zip extension — must be detected by PK\x03\x04 magic.
    let file_path = dir.path().join("bundle.dat");

    // Build a minimal stored ZIP with SECRET in one entry.
    let payload = b"SECRET";
    let zip_bytes = build_minimal_zip("secret.txt", payload);
    std::fs::write(&file_path, &zip_bytes)?;

    let sink = Arc::new(VecEventOutput::new());
    let cfg = LocalFsUringConfig {
        cpu_workers: 2,
        io_threads: 1,
        ring_entries: 64,
        io_depth: 16,
        chunk_size: 64,
        max_in_flight_files: 8,
        file_queue_cap: 8,
        pool_buffers: 32,
        use_registered_buffers: false,
        open_stat_mode: OpenStatMode::BlockingOnly,
        resolve_policy: ResolvePolicy::Default,
        follow_symlinks: false,
        max_file_size: None,
        seed: 123,
        dedupe_within_chunk: true,
        pin_threads: false,
        skip_binary: false,
        archive: ArchiveConfig::default(), // enabled=true
    };

    let (_summary, io_stats, _cpu_metrics) =
        scan_local_fs_uring(engine, &[dir.path().to_path_buf()], cfg, sink.clone())?;

    assert!(
        io_stats.archives_sniffed >= 1,
        "expected archives_sniffed >= 1, got {}",
        io_stats.archives_sniffed
    );

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);
    assert!(
        out_str.contains("secret"),
        "expected finding from sniff-detected ZIP archive; output: {out_str}"
    );

    Ok(())
}

/// Build a minimal stored ZIP archive with a single entry.
fn build_minimal_zip(name: &str, data: &[u8]) -> Vec<u8> {
    fn u16le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    let name_bytes = name.as_bytes();
    let mut crc = crc32fast::Hasher::new();
    crc.update(data);
    let crc32 = crc.finalize();

    let mut out = Vec::new();

    // Local file header
    out.extend_from_slice(&u32le(0x04034b50));
    out.extend_from_slice(&u16le(20));
    out.extend_from_slice(&u16le(0)); // flags
    out.extend_from_slice(&u16le(0)); // stored
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u32le(crc32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u16le(name_bytes.len() as u16));
    out.extend_from_slice(&u16le(0)); // extra len
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(data);

    // Central directory header
    let cd_start = out.len() as u32;
    out.extend_from_slice(&u32le(0x02014b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(20));
    out.extend_from_slice(&u16le(0)); // flags
    out.extend_from_slice(&u16le(0)); // stored
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u32le(crc32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u32le(data.len() as u32));
    out.extend_from_slice(&u16le(name_bytes.len() as u16));
    out.extend_from_slice(&u16le(0)); // extra len
    out.extend_from_slice(&u16le(0)); // comment len
    out.extend_from_slice(&u16le(0)); // disk number
    out.extend_from_slice(&u16le(0)); // internal attrs
    out.extend_from_slice(&u32le(0)); // external attrs
    out.extend_from_slice(&u32le(0)); // local header offset

    out.extend_from_slice(name_bytes);
    let cd_size = (out.len() as u32) - cd_start;

    // EOCD
    out.extend_from_slice(&u32le(0x06054b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(1));
    out.extend_from_slice(&u16le(1));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_start));
    out.extend_from_slice(&u16le(0)); // comment len

    out
}
