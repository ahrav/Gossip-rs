//! Real-ruleset baseline snapshot harness (Mode 2).
//!
//! Scans the curated fixture corpus at `tests/corpus/real_rules/fixtures/`
//! using the production gitleaks ruleset and compares findings against a
//! golden baseline at `tests/corpus/real_rules/expected/findings.json`.
//!
//! # Running
//!
//! ```bash
//! cargo test --features real-rules-harness --test simulation -- scanner_real_rules
//! ```
//!
//! # Updating the baseline
//!
//! ```bash
//! cargo test --features real-rules-harness --test simulation -- \
//!     scanner_real_rules::update_baseline --ignored --nocapture
//! ```
//!
//! See `docs/real_rules_harness_plan.md` for design rationale.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::scanner_rs::scheduler::local_fs_owner::{
    LocalConfig, LocalFile, VecFileSource, scan_local,
};
use crate::scanner_rs::unified::events::VecEventSink;
use crate::scanner_rs::{Engine, demo_transforms, demo_tuning};

/// Root of the fixture corpus relative to the workspace.
const CORPUS_DIR: &str = "tests/corpus/real_rules/fixtures";
/// Golden baseline path relative to the workspace.
const BASELINE_PATH: &str = "tests/corpus/real_rules/expected/findings.json";

// ============================================================================
// Baseline schema
// ============================================================================

/// A single normalized finding for baseline comparison.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct BaselineFinding {
    /// Relative path from the corpus root (forward slashes).
    path: String,
    /// Rule name (e.g. "aws-access-key-id").
    rule: String,
    /// Byte offset of the finding start.
    start: u64,
    /// Byte offset of the finding end.
    end: u64,
}

/// Top-level baseline file structure.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Baseline {
    schema_version: u32,
    #[serde(default)]
    metadata: BaselineMetadata,
    findings: Vec<BaselineFinding>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct BaselineMetadata {
    #[serde(default)]
    notes: String,
}

// ============================================================================
// Scanning
// ============================================================================

/// Discover all fixture files under `corpus_root`, recursively.
fn discover_fixtures(corpus_root: &Path) -> Vec<LocalFile> {
    let mut files = Vec::new();
    collect_files(corpus_root, &mut files);
    // Sort for deterministic scan order.
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

fn collect_files(dir: &Path, out: &mut Vec<LocalFile>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else if path.is_file() {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push(LocalFile { path, size });
        }
    }
}

/// Build an `Engine` from the real gitleaks ruleset with production transforms and tuning.
fn build_real_engine() -> Engine {
    let rules = crate::scanner_rs::demo_rules();
    Engine::new(rules, demo_transforms(), demo_tuning())
}

/// Scan the fixture corpus and return normalized, sorted findings.
fn scan_corpus() -> Vec<BaselineFinding> {
    let corpus_root = PathBuf::from(CORPUS_DIR);
    assert!(
        corpus_root.is_dir(),
        "fixture corpus not found at {CORPUS_DIR}"
    );

    let files = discover_fixtures(&corpus_root);
    assert!(!files.is_empty(), "no fixture files found");

    let engine = Arc::new(build_real_engine());
    let event_sink = Arc::new(VecEventSink::new());

    let cfg = LocalConfig {
        workers: 2,
        chunk_size: 64 * 1024,
        pool_buffers: 8,
        event_sink: event_sink.clone(),
        ..LocalConfig::default()
    };

    let source = VecFileSource::new(files);
    let _report = scan_local(engine, source, cfg);

    // Parse JSONL events to extract findings.
    let raw = event_sink.take();
    let jsonl = String::from_utf8_lossy(&raw);

    let mut findings = Vec::new();
    for line in jsonl.lines() {
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("finding") {
            continue;
        }
        let raw_path = v["path"].as_str().unwrap_or("");
        // Normalize to relative path from corpus root.
        let rel_path = normalize_path(raw_path, &corpus_root);
        findings.push(BaselineFinding {
            path: rel_path,
            rule: v["rule"].as_str().unwrap_or("").to_string(),
            start: v["start"].as_u64().unwrap_or(0),
            end: v["end"].as_u64().unwrap_or(0),
        });
    }

    findings.sort();
    findings.dedup();
    findings
}

/// Normalize an absolute path to a relative path from the corpus root using forward slashes.
fn normalize_path(raw: &str, corpus_root: &Path) -> String {
    let p = Path::new(raw);
    // Try direct strip first, then fall back to canonical forms.
    let rel = if let Ok(r) = p.strip_prefix(corpus_root) {
        r.to_path_buf()
    } else {
        let canon_root = corpus_root
            .canonicalize()
            .unwrap_or_else(|_| corpus_root.to_path_buf());
        let canon_p = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        canon_p
            .strip_prefix(&canon_root)
            .map(|r| r.to_path_buf())
            .unwrap_or_else(|_| p.to_path_buf())
    };
    // Convert to forward slashes for cross-platform determinism.
    rel.to_string_lossy().replace('\\', "/")
}

/// Load the golden baseline from disk.
fn load_baseline() -> Baseline {
    let path = PathBuf::from(BASELINE_PATH);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read baseline at {}: {e}", path.display()));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("failed to parse baseline at {}: {e}", path.display()))
}

/// Write the baseline to disk.
fn write_baseline(findings: &[BaselineFinding]) {
    let baseline = Baseline {
        schema_version: 1,
        metadata: BaselineMetadata {
            notes: "Generated by real rules harness baseline update command.".to_string(),
        },
        findings: findings.to_vec(),
    };
    let json = serde_json::to_string_pretty(&baseline).expect("failed to serialize baseline");
    std::fs::write(BASELINE_PATH, json + "\n").expect("failed to write baseline");
}

// ============================================================================
// Tests
// ============================================================================

/// Main regression test: scan corpus and compare to golden baseline.
#[test]
fn baseline_comparison() {
    let actual = scan_corpus();
    let baseline = load_baseline();
    let expected = baseline.findings;

    if actual == expected {
        eprintln!(
            "real rules harness: {} findings match baseline",
            actual.len()
        );
        return;
    }

    // Build a human-readable diff.
    let mut added = Vec::new();
    let mut removed = Vec::new();

    // Findings in actual but not in expected.
    for f in &actual {
        if !expected.contains(f) {
            added.push(f);
        }
    }
    // Findings in expected but not in actual.
    for f in &expected {
        if !actual.contains(f) {
            removed.push(f);
        }
    }

    let mut msg = format!(
        "Baseline mismatch: {} actual vs {} expected\n",
        actual.len(),
        expected.len()
    );
    if !added.is_empty() {
        msg.push_str(&format!("\n  +{} new findings:\n", added.len()));
        for f in &added {
            msg.push_str(&format!(
                "    + {}:{} [{}-{}]\n",
                f.path, f.rule, f.start, f.end
            ));
        }
    }
    if !removed.is_empty() {
        msg.push_str(&format!("\n  -{} missing findings:\n", removed.len()));
        for f in &removed {
            msg.push_str(&format!(
                "    - {}:{} [{}-{}]\n",
                f.path, f.rule, f.start, f.end
            ));
        }
    }
    msg.push_str("\nRun the update_baseline test to regenerate:\n");
    msg.push_str("  cargo test --features real-rules-harness --test simulation -- \\\n");
    msg.push_str("      scanner_real_rules::update_baseline --ignored --nocapture\n");

    panic!("{msg}");
}

/// Regenerate the golden baseline from a fresh scan.
///
/// This test is `#[ignore]`d so it only runs when explicitly requested.
#[test]
#[ignore]
fn update_baseline() {
    let findings = scan_corpus();
    write_baseline(&findings);
    eprintln!(
        "Baseline updated: {} findings written to {BASELINE_PATH}",
        findings.len()
    );
}
