//! Integration tests for binary-aware content policy.
//!
//! # Scope
//!
//! These tests exercise the FS scanning path's binary file skipping,
//! binary text extraction, and the `--scan-binary` override behavior.
//!
//! Run with: `cargo test --test integration`

use scanner_scheduler::events::EventOutput;
use scanner_scheduler::events::VecEventOutput;
use scanner_scheduler::scheduler::engine_stub::{MockEngine, MockRule};
use scanner_scheduler::scheduler::local_fs_owner::{
    LocalConfig, LocalFile, VecFileSource, scan_local,
};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;

/// Extract a JSON string value for a given key from a single JSON line.
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

fn finding_paths(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|l| l.contains("\"type\":\"finding\""))
        .filter_map(|l| extract_json_string(l, "path"))
        .collect()
}

fn lf(path: PathBuf, size: u64) -> LocalFile {
    LocalFile { path, size }
}

fn run_scan_with_config(
    files: Vec<LocalFile>,
    mut cfg: LocalConfig,
) -> (
    String,
    scanner_scheduler::scheduler::local_fs_owner::LocalReport,
) {
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

fn default_cfg() -> LocalConfig {
    LocalConfig {
        workers: 1,
        chunk_size: 64,
        ..LocalConfig::default()
    }
}

/// Binary files (containing NUL bytes) should be skipped by default.
#[test]
fn fs_scan_skips_binary_files() {
    let dir = TempDir::new().unwrap();

    // Binary file with NUL bytes.
    let bin_path = dir.path().join("image.png");
    let mut f = std::fs::File::create(&bin_path).unwrap();
    f.write_all(b"\x89PNG\r\n\x1a\n\x00SECRET").unwrap();
    let bin_size = std::fs::metadata(&bin_path).unwrap().len();

    // Text file with the secret.
    let txt_path = dir.path().join("config.txt");
    std::fs::write(&txt_path, b"password=SECRET\n").unwrap();
    let txt_size = std::fs::metadata(&txt_path).unwrap().len();

    let files = vec![lf(bin_path, bin_size), lf(txt_path, txt_size)];

    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    // Secret should be found in text file, not in binary file.
    assert!(
        paths.iter().any(|p| p.contains("config.txt")),
        "expected finding in config.txt: {output}"
    );
    assert!(
        !paths.iter().any(|p| p.contains("image.png")),
        "binary file should be skipped: {output}"
    );

    // Extension skip counter should be incremented (.png is in the skip set).
    assert!(
        report.metrics.ext_skipped > 0,
        "expected ext_skipped > 0, got {}",
        report.metrics.ext_skipped
    );
}

/// With `skip_binary = false`, binary files should be scanned.
#[test]
fn fs_scan_binary_flag_overrides_skip() {
    let dir = TempDir::new().unwrap();

    // Binary file with NUL bytes but also contains the secret pattern.
    let bin_path = dir.path().join("data.bin");
    let mut f = std::fs::File::create(&bin_path).unwrap();
    f.write_all(b"\x00\x00SECRET\x00\x00").unwrap();
    let size = std::fs::metadata(&bin_path).unwrap().len();

    let files = vec![lf(bin_path, size)];

    let mut cfg = default_cfg();
    cfg.skip_binary = false;

    let (output, _report) = run_scan_with_config(files, cfg);
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("data.bin")),
        "with skip_binary=false, binary file should be scanned: {output}"
    );
}

/// Text files should always be scanned (not incorrectly classified as binary).
#[test]
fn fs_scan_text_files_not_skipped() {
    let dir = TempDir::new().unwrap();

    let txt_path = dir.path().join("app.py");
    std::fs::write(&txt_path, b"api_key = 'SECRET'\n").unwrap();
    let size = std::fs::metadata(&txt_path).unwrap().len();

    let files = vec![lf(txt_path, size)];
    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("app.py")),
        "text file should be scanned: {output}"
    );
    assert_eq!(
        report.metrics.binary_skipped, 0,
        "no binary files should be skipped"
    );
}

/// .ipynb files should be detected as extractable and have their code cells scanned.
#[test]
fn fs_scan_ipynb_extraction() {
    let dir = TempDir::new().unwrap();

    let nb_path = dir.path().join("notebook.ipynb");
    let notebook_json = r##"{
        "cells": [
            {
                "cell_type": "code",
                "source": ["api_key = 'SECRET'\n"]
            }
        ]
    }"##;
    std::fs::write(&nb_path, notebook_json).unwrap();
    let size = std::fs::metadata(&nb_path).unwrap().len();

    let files = vec![lf(nb_path, size)];
    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("notebook.ipynb")),
        "ipynb extraction should find secret: {output}"
    );
    assert!(
        report.metrics.binary_extracted > 0,
        "expected binary_extracted > 0, got {}",
        report.metrics.binary_extracted
    );
}

/// .env files should be parsed as structured extractable content.
#[test]
fn fs_scan_dotenv_extraction() {
    let dir = TempDir::new().unwrap();

    let env_path = dir.path().join(".env");
    std::fs::write(
        &env_path,
        b"# comment\nexport API_KEY=\"SECRET\"\nIGNORED_LINE\n",
    )
    .unwrap();
    let size = std::fs::metadata(&env_path).unwrap().len();

    let files = vec![lf(env_path, size)];
    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains(".env")),
        "dotenv extraction should find secret: {output}"
    );
    assert!(
        report.metrics.binary_extracted > 0,
        "expected binary_extracted > 0, got {}",
        report.metrics.binary_extracted
    );
}

/// .class files should be detected as extractable and have their constant pool strings scanned.
#[test]
fn fs_scan_java_class_extraction() {
    let dir = TempDir::new().unwrap();

    // Build a minimal .class file with SECRET in the constant pool.
    let class_path = dir.path().join("App.class");
    let mut class_data = Vec::new();
    // CAFEBABE magic.
    class_data.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    // Minor/major version (Java 8).
    class_data.extend_from_slice(&[0, 0, 0, 52]);
    // Constant pool count = 2 (one entry at index 1).
    class_data.extend_from_slice(&2u16.to_be_bytes());
    // Entry 1: CONSTANT_Utf8 containing "SECRET"
    class_data.push(1); // tag
    class_data.extend_from_slice(&6u16.to_be_bytes());
    class_data.extend_from_slice(b"SECRET");
    std::fs::write(&class_path, &class_data).unwrap();
    let size = std::fs::metadata(&class_path).unwrap().len();

    let files = vec![lf(class_path, size)];
    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("App.class")),
        "class extraction should find secret: {output}"
    );
    assert!(
        report.metrics.binary_extracted > 0,
        "expected binary_extracted > 0, got {}",
        report.metrics.binary_extracted
    );
}

/// .jar files should be detected as extractable and have embedded .class strings scanned.
/// Archive scanning is disabled so the JAR goes through the extraction path.
#[test]
fn fs_scan_jar_extraction() {
    let dir = TempDir::new().unwrap();

    // Build a minimal .class file with SECRET.
    let mut class_data = Vec::new();
    class_data.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    class_data.extend_from_slice(&[0, 0, 0, 52]);
    class_data.extend_from_slice(&2u16.to_be_bytes());
    class_data.push(1);
    class_data.extend_from_slice(&6u16.to_be_bytes());
    class_data.extend_from_slice(b"SECRET");

    // Wrap in a JAR (ZIP).
    let jar_path = dir.path().join("app.jar");
    let buf = Vec::new();
    let cursor = std::io::Cursor::new(buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("com/example/App.class", options).unwrap();
    std::io::Write::write_all(&mut writer, &class_data).unwrap();
    let cursor = writer.finish().unwrap();
    std::fs::write(&jar_path, cursor.into_inner()).unwrap();
    let size = std::fs::metadata(&jar_path).unwrap().len();

    let files = vec![lf(jar_path, size)];
    // Disable archive scanning so the JAR hits the extraction path
    // (otherwise ZIP magic routes it through archive scanning instead).
    let mut cfg = default_cfg();
    cfg.archive.enabled = false;
    let (output, report) = run_scan_with_config(files, cfg);
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("app.jar")),
        "jar extraction should find secret: {output}"
    );
    assert!(
        report.metrics.binary_extracted > 0,
        "expected binary_extracted > 0, got {}",
        report.metrics.binary_extracted
    );
}

/// .pyc files should be detected as extractable and have their marshal strings scanned.
#[test]
fn fs_scan_pyc_extraction() {
    let dir = TempDir::new().unwrap();

    // Build a minimal .pyc with a marshal string containing SECRET.
    let pyc_path = dir.path().join("module.pyc");
    let mut pyc_data = Vec::new();
    // Magic for Python 3.8 (0x550d) + \r\n.
    pyc_data.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]);
    // Flags = 0.
    pyc_data.extend_from_slice(&[0, 0, 0, 0]);
    // Timestamp.
    pyc_data.extend_from_slice(&[0, 0, 0, 0]);
    // Source size.
    pyc_data.extend_from_slice(&[0, 0, 0, 0]);
    // Marshal: TYPE_SHORT_ASCII (0x7a), length=6, "SECRET".
    pyc_data.push(0x7a); // 'z' = TYPE_SHORT_ASCII
    pyc_data.push(6);
    pyc_data.extend_from_slice(b"SECRET");
    std::fs::write(&pyc_path, &pyc_data).unwrap();
    let size = std::fs::metadata(&pyc_path).unwrap().len();

    let files = vec![lf(pyc_path, size)];
    let (output, report) = run_scan_with_config(files, default_cfg());
    let paths = finding_paths(&output);

    assert!(
        paths.iter().any(|p| p.contains("module.pyc")),
        "pyc extraction should find secret: {output}"
    );
    assert!(
        report.metrics.binary_extracted > 0,
        "expected binary_extracted > 0, got {}",
        report.metrics.binary_extracted
    );
}

/// Stats should report correct binary skip counts.
#[test]
fn binary_skip_stats_correct() {
    let dir = TempDir::new().unwrap();

    // Create 3 binary files and 2 text files.
    for i in 0..3 {
        let path = dir.path().join(format!("bin{i}.dat"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0u8; 100]).unwrap();
    }
    for i in 0..2 {
        let path = dir.path().join(format!("text{i}.txt"));
        std::fs::write(&path, b"hello world\n").unwrap();
    }

    let files: Vec<LocalFile> = (0..3)
        .map(|i| {
            let p = dir.path().join(format!("bin{i}.dat"));
            let s = std::fs::metadata(&p).unwrap().len();
            lf(p, s)
        })
        .chain((0..2).map(|i| {
            let p = dir.path().join(format!("text{i}.txt"));
            let s = std::fs::metadata(&p).unwrap().len();
            lf(p, s)
        }))
        .collect();

    let (_, report) = run_scan_with_config(files, default_cfg());

    assert_eq!(
        report.metrics.ext_skipped, 3,
        "expected 3 files extension-skipped, got {}",
        report.metrics.ext_skipped
    );
}

/// Binary file with no archive magic should be classified as binary (not
/// archive) when both archive sniffing and binary skipping are enabled.
/// Validates the sequential logic: sniff first, binary check second.
#[test]
fn binary_file_classified_after_sniff_fails() {
    let dir = TempDir::new().unwrap();

    // Binary content: NUL bytes but no archive magic.
    // Use .xyz extension (not in the extension skip set) so the content
    // probe is actually exercised rather than short-circuiting on extension.
    let bin_path = dir.path().join("data.xyz");
    std::fs::write(&bin_path, b"\x00\x01SECRET\x00\x02").unwrap();
    let size = std::fs::metadata(&bin_path).unwrap().len();

    let files = vec![lf(bin_path, size)];

    let mut cfg = default_cfg();
    cfg.archive.enabled = true;
    cfg.skip_binary = true;

    let (output, report) = run_scan_with_config(files, cfg);
    let paths = finding_paths(&output);

    // File should be skipped as binary, not routed as archive.
    assert!(
        paths.is_empty(),
        "binary file with no archive magic should produce no findings: {output}"
    );
    assert!(
        report.metrics.binary_skipped > 0,
        "expected binary_skipped > 0, got {}",
        report.metrics.binary_skipped
    );
}
