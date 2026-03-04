use std::path::PathBuf;

use gossip_scan_driver::GitDebugLevel;
use scanner_engine::TransformId;
use scanner_git::{GitScanMode, MergeDiffMode};
use scanner_scheduler::source_kind::SourceKind;

use super::*;
use crate::{AnchorMode, EventFormat, ExecutionMode, ScanBudgets, TransformFilter};

#[test]
fn parse_fs_cli_config_supports_extended_flags() {
    let cfg = parse_args_from([
        "scan".into(),
        "fs".into(),
        "--path".into(),
        "/tmp/workdir".into(),
        "--execution-mode=connector".into(),
        "--max-items=12".into(),
        "--max-bytes=4096".into(),
        "--workers".into(),
        "2".into(),
        "--decode-depth=1".into(),
        "--skip-archives".into(),
        "--scan-binary".into(),
        "--persist-findings".into(),
        "--anchors=derived".into(),
        "--event-format=text".into(),
        "--verbose".into(),
        "--null-sink".into(),
        "--transforms=none".into(),
        "--rules=/tmp/custom.yaml".into(),
    ])
    .expect("parse fs config");

    assert_eq!(
        cfg,
        CliConfig {
            source: CliSource::Fs {
                path: PathBuf::from("/tmp/workdir"),
            },
            execution_mode: ExecutionMode::Connector,
            budgets: ScanBudgets {
                max_items: 12,
                max_bytes: 4096,
            },
            null_sink: true,
            event_format: EventFormat::Text,
            verbose: true,
            summary_debug: false,
            rules_file: Some(PathBuf::from("/tmp/custom.yaml")),
            transform_filter: TransformFilter::None,
            workers: Some(2),
            decode_depth: Some(1),
            skip_archives: true,
            scan_binary: true,
            persist_findings: true,
            anchor_mode: AnchorMode::Derived,
            debug_level: GitDebugLevel::Off,
            enrich_identities: false,
            git_repo_id: 1,
            git_scan_mode: GitScanMode::OdbBlobFast,
            git_merge_mode: MergeDiffMode::AllParents,
            git_tree_delta_cache_mb: None,
            git_engine_chunk_mb: None,
        }
    );
}

#[test]
fn parse_transforms_csv_variant() {
    let cfg = parse_args_from([
        "scan".into(),
        "fs".into(),
        "--path=/tmp/workdir".into(),
        "--transforms=url,base64,url".into(),
    ])
    .expect("parse fs config");

    assert_eq!(
        cfg.transform_filter,
        TransformFilter::Only(vec![TransformId::UrlPercent, TransformId::Base64])
    );
}

#[test]
fn parse_git_cli_config_with_positional_repo() {
    let cfg = parse_args_from([
        "scan".into(),
        "git".into(),
        "/tmp/repo".into(),
        "--execution-mode".into(),
        "direct".into(),
        "--event-format=json".into(),
    ])
    .expect("parse git config");

    assert_eq!(
        cfg,
        CliConfig {
            source: CliSource::Git {
                repo: PathBuf::from("/tmp/repo"),
            },
            execution_mode: ExecutionMode::Direct,
            budgets: ScanBudgets::default(),
            null_sink: false,
            event_format: EventFormat::Json,
            verbose: false,
            summary_debug: false,
            rules_file: None,
            transform_filter: TransformFilter::All,
            workers: None,
            decode_depth: None,
            skip_archives: false,
            scan_binary: false,
            persist_findings: false,
            anchor_mode: AnchorMode::Manual,
            debug_level: GitDebugLevel::Off,
            enrich_identities: false,
            git_repo_id: 1,
            git_scan_mode: GitScanMode::OdbBlobFast,
            git_merge_mode: MergeDiffMode::AllParents,
            git_tree_delta_cache_mb: None,
            git_engine_chunk_mb: None,
        }
    );
}

#[test]
fn parse_git_cli_config_supports_extended_flags() {
    let cfg = parse_args_from([
        "scan".into(),
        "git".into(),
        "--repo".into(),
        "/tmp/repo".into(),
        "--execution-mode=connector".into(),
        "--max-items=12".into(),
        "--max-bytes=4096".into(),
        "--x-pack-exec-workers=9".into(),
        "--workers".into(),
        "2".into(),
        "--decode-depth".into(),
        "1".into(),
        "--scan-binary".into(),
        "--debug=perf".into(),
        "--debug".into(),
        "--enrich-identities".into(),
        "--anchors=derived".into(),
        "--event-format=text".into(),
        "--verbose".into(),
        "--null-sink".into(),
        "--transforms=none".into(),
        "--rules=/tmp/custom.yaml".into(),
        "--x-repo-id=42".into(),
        "--x-mode=diff".into(),
        "--x-merge=first-parent".into(),
        "--x-tree-delta-cache-mb=256".into(),
        "--x-engine-chunk-mb=4".into(),
    ])
    .expect("parse git config");

    assert_eq!(
        cfg,
        CliConfig {
            source: CliSource::Git {
                repo: PathBuf::from("/tmp/repo"),
            },
            execution_mode: ExecutionMode::Connector,
            budgets: ScanBudgets {
                max_items: 12,
                max_bytes: 4096,
            },
            null_sink: true,
            event_format: EventFormat::Text,
            verbose: true,
            summary_debug: true,
            rules_file: Some(PathBuf::from("/tmp/custom.yaml")),
            transform_filter: TransformFilter::None,
            workers: Some(2),
            decode_depth: Some(1),
            skip_archives: false,
            scan_binary: true,
            persist_findings: false,
            anchor_mode: AnchorMode::Derived,
            debug_level: GitDebugLevel::Perf,
            enrich_identities: true,
            git_repo_id: 42,
            git_scan_mode: GitScanMode::DiffHistory,
            git_merge_mode: MergeDiffMode::FirstParentOnly,
            git_tree_delta_cache_mb: Some(256),
            git_engine_chunk_mb: Some(4),
        }
    );
}

#[test]
fn parse_git_x_pack_exec_workers_sets_workers_when_public_workers_missing() {
    let cfg = parse_args_from([
        "scan".into(),
        "git".into(),
        "--repo=/tmp/repo".into(),
        "--x-pack-exec-workers=7".into(),
    ])
    .expect("parse git config");

    assert_eq!(cfg.workers, Some(7));
}

#[test]
fn parse_git_debug_space_value_sets_perf_level() {
    let cfg = parse_args_from([
        "scan".into(),
        "git".into(),
        "--repo=/tmp/repo".into(),
        "--debug".into(),
        "perf".into(),
    ])
    .expect("parse git config");

    assert_eq!(cfg.debug_level, GitDebugLevel::Perf);
    assert!(cfg.summary_debug);
}

#[test]
fn parse_fs_debug_flag_enables_summary_debug() {
    let cfg = parse_args_from([
        "scan".into(),
        "fs".into(),
        "--path=/tmp/workdir".into(),
        "--debug".into(),
    ])
    .expect("parse fs config");

    assert!(cfg.summary_debug);
    assert_eq!(cfg.debug_level, GitDebugLevel::Off);
}

#[test]
fn parse_fs_debug_value_is_rejected() {
    let err = parse_args_from([
        "scan".into(),
        "fs".into(),
        "--path=/tmp/workdir".into(),
        "--debug=perf".into(),
    ])
    .expect_err("debug value should fail for fs scans");

    match err {
        CliError::Usage(message) => {
            assert!(message.contains("--debug does not accept a value"))
        }
        other => panic!("expected usage error, got {other:?}"),
    }
}

#[test]
fn git_help_text_omits_hidden_x_flags() {
    let usage = source_usage("git");
    assert!(usage.contains("--debug"));
    assert!(usage.contains("--enrich-identities"));
    assert!(!usage.contains("--x-mode"));
    assert!(!usage.contains("--x-repo-id"));
}

#[test]
fn default_summary_omits_workers_but_keeps_errors_for_git() {
    let report = gossip_scan_driver::ScanReport {
        items_scanned: 5,
        bytes_scanned: 10,
        chunks_scanned: 2,
        findings_emitted: 1,
        errors: 3,
        ..gossip_scan_driver::ScanReport::default()
    };
    let summary = render_scan_summary(
        &report,
        std::time::Duration::from_millis(10),
        4,
        SourceKind::Git,
        false,
    );
    assert!(summary.contains("errors=3\n"));
    assert!(!summary.contains("workers="));
}

#[test]
fn debug_summary_includes_extended_fs_metrics() {
    let report = gossip_scan_driver::ScanReport {
        items_scanned: 9,
        bytes_scanned: 1024,
        chunks_scanned: 3,
        findings_emitted: 4,
        errors: 1,
        binary_skipped: 7,
        ext_skipped: 8,
        lock_skipped: 9,
        binary_extracted: 2,
        dropped_findings: 5,
        persist_emit_failures: 6,
        persist_incomplete: true,
        scan_ns: 11_000_000,
        persist_ns: 2_000_000,
    };
    let summary = render_scan_summary(
        &report,
        std::time::Duration::from_millis(20),
        12,
        SourceKind::Fs,
        true,
    );
    for key in [
        "workers=12",
        "binary_skipped=7",
        "ext_skipped=8",
        "lock_skipped=9",
        "binary_extracted=2",
        "dropped_findings=5",
        "persist_emit_failures=6",
        "persist_incomplete=1",
        "init_ms=7",
        "scan_ms=11",
        "persist_ms=2",
    ] {
        assert!(summary.contains(key), "missing key: {key}");
    }
}

#[test]
fn fs_debug_timing_components_sum_to_elapsed() {
    // When scan_ns and persist_ns are both non-zero, the debug output
    // shows init_ms, scan_ms, and persist_ms. These three components
    // must be non-overlapping and sum to elapsed_ms exactly.
    let report = gossip_scan_driver::ScanReport {
        items_scanned: 1,
        bytes_scanned: 100,
        chunks_scanned: 1,
        findings_emitted: 0,
        errors: 0,
        scan_ns: 11_000_000,   // 11ms
        persist_ns: 2_000_000, // 2ms
        ..gossip_scan_driver::ScanReport::default()
    };
    let elapsed = std::time::Duration::from_millis(20);
    let summary = render_scan_summary(&report, elapsed, 4, SourceKind::Fs, true);

    // Parse the three timing components from the summary output.
    let parse_val = |key: &str| -> u64 {
        summary
            .lines()
            .find(|l| l.starts_with(key))
            .unwrap_or_else(|| panic!("missing key: {key}"))
            .strip_prefix(key)
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    let init_ms = parse_val("init_ms=");
    let scan_ms = parse_val("scan_ms=");
    let persist_ms = parse_val("persist_ms=");
    let elapsed_ms = 20u64;

    assert_eq!(
        init_ms + scan_ms + persist_ms,
        elapsed_ms,
        "timing components must sum to elapsed: init={init_ms} + scan={scan_ms} + persist={persist_ms} = {} != {elapsed_ms}",
        init_ms + scan_ms + persist_ms,
    );
}

#[test]
fn parse_help_returns_help_error() {
    let err = parse_args_from(["--help".into()]).expect_err("expected help result");
    assert!(matches!(err, CliError::HelpRequested(_)));
}
