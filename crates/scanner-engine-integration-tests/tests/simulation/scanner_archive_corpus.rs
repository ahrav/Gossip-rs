#![cfg(any(test, feature = "sim-harness"))]
//! Deterministic archive simulation cases for regression coverage.
//!
//! Focus areas: long names, duplicate locators, traversal/clamping, encrypted
//! entries, truncated archives, nested archives, budget caps (entry/archive/root),
//! path-budget enforcement, gzip name fallback, and directory entries.

use std::collections::BTreeMap;

use crate::scanner_rs::archive::ArchiveConfig;
use crate::scanner_rs::sim::FaultPlan;
use crate::scanner_rs::sim::fs::{SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
use crate::scanner_rs::sim_archive::{
    entry_paths, materialize_archive, materialize_archive_with_paths,
};
use crate::scanner_rs::sim_scanner::{
    ArchiveCorruptionSpec, ArchiveEntrySpec, ArchiveFileSpec, ArchiveKindSpec,
    EntryCompressionSpec, EntryKindSpec, ExpectedDisposition, ExpectedSecret, RuleSuiteSpec,
    RunConfig, RunOutcome, ScannerSimRunner, Scenario, ScenarioGenConfig, SecretRepr, SpanU32,
    SyntheticRuleSpec, build_engine_from_suite, generate_scenario,
};

const SCHEMA_VERSION: u32 = 1;
const SECRET_PRIMARY: &[u8] = b"SIM0_AB12";
const SECRET_SECONDARY: &[u8] = b"SIM0_CD34";

#[test]
fn archive_corpus_smoke() {
    let archive_cfg = ArchiveConfig {
        enabled: true,
        ..ArchiveConfig::default()
    };

    let gen_cfg = ScenarioGenConfig {
        file_count: 0,
        archive_count: 1,
        archive_entries: 2,
        secrets_per_file: 2,
        representations: vec![SecretRepr::Raw],
        archive: archive_cfg.clone(),
        ..ScenarioGenConfig::default()
    };

    let scenario = generate_scenario(2025, &gen_cfg).expect("generate scenario");
    let mut run_cfg = RunConfig {
        workers: 1,
        chunk_size: 64,
        overlap: 64,
        max_in_flight_objects: 4,
        buffer_pool_cap: 4,
        max_file_size: u64::MAX,
        max_steps: 0,
        max_transform_depth: 2,
        scan_utf16_variants: true,
        archive: archive_cfg,
        stability_runs: 1,
        archive_deadline_countdown: None,
    };

    let engine = build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine");
    let required = engine.required_overlap() as u32;
    if run_cfg.overlap < required {
        run_cfg.overlap = required;
    }
    if run_cfg.chunk_size < run_cfg.overlap {
        run_cfg.chunk_size = run_cfg.overlap;
    }

    let runner = ScannerSimRunner::new(run_cfg, 0xC0FF_EE10);
    let fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    match runner.run(&scenario, &engine, &fault_plan) {
        RunOutcome::Ok { .. } => {}
        RunOutcome::Failed(fail) => {
            panic!("archive corpus sim failed: {fail:?}");
        }
    }
}

#[test]
fn archive_zip_long_name_deflate_truncation() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_virtual_path_len_per_entry = 32;
    archive_cfg.max_virtual_path_bytes_per_archive = 1024;

    let long_name = vec![b'a'; 200];
    let (payload, span) = payload_with_secret(8, 8);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"longname.zip".to_vec()),
        kind: ArchiveKindSpec::Zip,
        entries: vec![ArchiveEntrySpec {
            name_bytes: long_name,
            payload,
            compression: EntryCompressionSpec::Deflate,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE11);
}

#[test]
fn archive_tar_duplicate_names_unique_locators() {
    let archive_cfg = base_archive_config();

    let (payload_a, span_a) = payload_with_secret(4, 4);
    let (payload_b, span_b) = payload_with_secret(12, 6);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"dups.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"dup.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"dup.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let scenario = build_archive_scenario(
        &archive_cfg,
        spec,
        vec![
            ExpectedSpec::must_find(0, span_a),
            ExpectedSpec::must_find(1, span_b),
        ],
    );
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE12);
}

#[test]
fn archive_tar_traversal_and_component_cap() {
    let archive_cfg = base_archive_config();

    let (payload_a, span_a) = payload_with_secret(2, 2);
    let (payload_b, span_b) = payload_with_secret(6, 6);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"paths.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"../safe/../secret.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: component_cap_name(300),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let scenario = build_archive_scenario(
        &archive_cfg,
        spec,
        vec![
            ExpectedSpec::must_find(0, span_a),
            ExpectedSpec::must_find(1, span_b),
        ],
    );
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE13);
}

#[test]
fn archive_zip_encrypted_entry_is_skipped() {
    let archive_cfg = base_archive_config();

    let (payload, _span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"encrypted.zip".to_vec()),
        kind: ArchiveKindSpec::Zip,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"secret.txt".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: true,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    // Encrypted entries should be skipped. Any finding here is an unexpected
    // success and should fail the oracle.
    // Truncated archives should not surface findings for entries that never
    // become visible.
    let scenario = build_archive_scenario(&archive_cfg, spec, Vec::new());
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE14);
}

#[test]
fn archive_targz_truncated_archive_is_handled() {
    let archive_cfg = base_archive_config();

    let (payload, _span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"truncated.tar.gz".to_vec()),
        kind: ArchiveKindSpec::TarGz,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"inner.txt".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: Some(ArchiveCorruptionSpec::TruncateTo { len: 8 }),
    };

    let scenario = build_archive_scenario(&archive_cfg, spec, Vec::new());
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE15);
}

#[test]
fn archive_tarbz2_smoke() {
    let archive_cfg = base_archive_config();

    let (payload, span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"smoke.tar.bz2".to_vec()),
        kind: ArchiveKindSpec::TarBz2,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"inner.txt".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE15A);
}

#[test]
fn archive_entry_cap_enforced() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_entries_per_archive = 1;

    let (payload_a, span_a) = payload_with_secret(4, 4);
    let (payload_b, _span_b) = payload_with_secret(8, 8);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"entrycap.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"first.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"second.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    // Only the first entry should be scanned; if the cap is ignored, the second
    // secret becomes an unexpected finding and the test fails.
    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE16);
}

#[test]
fn archive_nested_tar_scans_inner() {
    let archive_cfg = base_archive_config();

    let (payload, span) = payload_with_secret(4, 4);
    let inner_entries = vec![ArchiveEntrySpec {
        name_bytes: b"inner.txt".to_vec(),
        payload,
        compression: EntryCompressionSpec::Store,
        encrypted: false,
        kind: EntryKindSpec::RegularFile,
    }];

    let nested = build_nested_archive_case(
        &archive_cfg,
        b"outer.tar",
        ArchiveKindSpec::Tar,
        b"inner.tar",
        ArchiveKindSpec::Tar,
        inner_entries,
    );

    let expected = vec![ExpectedSecret {
        path: SimPath::new(nested.inner_entry_paths[0].clone()),
        rule_id: 0,
        root_span: span,
        repr: SecretRepr::Raw,
        disposition: ExpectedDisposition::MustFind,
    }];

    let scenario =
        build_scenario_with_archives(vec![(nested.outer_spec, nested.outer_bytes)], expected);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE17);
}

#[test]
fn archive_depth_cap_scans_raw_outer_path() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_archive_depth = 1;

    let (payload, _span) = payload_with_secret(4, 4);
    let inner_entries = vec![ArchiveEntrySpec {
        name_bytes: b"inner.txt".to_vec(),
        payload,
        compression: EntryCompressionSpec::Store,
        encrypted: false,
        kind: EntryKindSpec::RegularFile,
    }];

    let nested = build_nested_archive_case(
        &archive_cfg,
        b"outer.tar",
        ArchiveKindSpec::Tar,
        b"inner.tar",
        ArchiveKindSpec::Tar,
        inner_entries,
    );
    let span = span_for_pattern(&nested.inner_bytes, SECRET_PRIMARY);

    let expected = vec![ExpectedSecret {
        path: SimPath::new(nested.outer_entry_paths[0].clone()),
        rule_id: 0,
        root_span: span,
        repr: SecretRepr::Raw,
        disposition: ExpectedDisposition::MustFind,
    }];

    let scenario =
        build_scenario_with_archives(vec![(nested.outer_spec, nested.outer_bytes)], expected);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE18);
}

#[test]
fn archive_entry_byte_cap_limits_scan() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_uncompressed_bytes_per_entry = 20;
    archive_cfg.max_total_uncompressed_bytes_per_archive = 64;
    archive_cfg.max_total_uncompressed_bytes_per_root = 64;

    let (payload, span_a, _span_b) = payload_with_two_secrets(4, 16, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"entrycap-bytes.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"cap.txt".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE19);
}

#[test]
fn archive_tarbz2_entry_byte_cap_limits_scan() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_uncompressed_bytes_per_entry = 20;
    archive_cfg.max_total_uncompressed_bytes_per_archive = 64;
    archive_cfg.max_total_uncompressed_bytes_per_root = 64;

    let (payload, span_a, _span_b) = payload_with_two_secrets(4, 16, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"entrycap-bytes.tar.bz2".to_vec()),
        kind: ArchiveKindSpec::TarBz2,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"cap.txt".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE19A);
}

#[test]
fn archive_archive_byte_cap_limits_scan() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_uncompressed_bytes_per_entry = 20;
    archive_cfg.max_total_uncompressed_bytes_per_archive = 20;
    archive_cfg.max_total_uncompressed_bytes_per_root = 40;

    let (payload_a, span_a) = payload_with_secret(2, 9);
    let (payload_b, _span_b) = payload_with_secret(2, 9);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"archivecap.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"first.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"second.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE1A);
}

#[test]
fn archive_root_byte_cap_limits_scan() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_uncompressed_bytes_per_entry = 20;
    archive_cfg.max_total_uncompressed_bytes_per_archive = 20;
    archive_cfg.max_total_uncompressed_bytes_per_root = 24;

    let (payload_a, span_a) = payload_with_secret(2, 9);
    let (payload_b, _span_b) = payload_with_secret(10, 1);

    let inner_spec_a = ArchiveFileSpec {
        root_path: SimPath::new(b"inner-a.tmp".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"first.txt".to_vec(),
            payload: payload_a,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };
    let inner_spec_b = ArchiveFileSpec {
        root_path: SimPath::new(b"inner-b.tmp".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"second.txt".to_vec(),
            payload: payload_b,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let inner_mat_a = materialize_archive(&inner_spec_a).expect("materialize inner a");
    let inner_mat_b = materialize_archive(&inner_spec_b).expect("materialize inner b");

    let outer_spec = ArchiveFileSpec {
        root_path: SimPath::new(b"rootcap.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"inner-a.tar".to_vec(),
                payload: inner_mat_a.bytes.clone(),
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"inner-b.tar".to_vec(),
                payload: inner_mat_b.bytes.clone(),
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let (outer_bytes, outer_paths) =
        materialize_archive_with_paths(&outer_spec, &archive_cfg).expect("materialize outer");

    let inner_path_spec_a = ArchiveFileSpec {
        root_path: SimPath::new(outer_paths[0].clone()),
        kind: ArchiveKindSpec::Tar,
        entries: inner_spec_a.entries.clone(),
        corruption: None,
    };
    let inner_paths_a =
        entry_paths(&inner_path_spec_a, &inner_mat_a, &archive_cfg).expect("inner paths a");

    let expected = vec![ExpectedSecret {
        path: SimPath::new(inner_paths_a[0].clone()),
        rule_id: 0,
        root_span: span_a,
        repr: SecretRepr::Raw,
        disposition: ExpectedDisposition::MustFind,
    }];

    let scenario = build_scenario_with_archives(vec![(outer_spec, outer_bytes)], expected);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE1B);
}

#[test]
fn archive_path_budget_caps_virtual_paths() {
    let mut archive_cfg = base_archive_config();
    archive_cfg.max_virtual_path_len_per_entry = 48;
    archive_cfg.max_virtual_path_bytes_per_archive = 48;

    let (payload_a, span_a) = payload_with_secret(4, 4);
    let (payload_b, _span_b) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"pathcap.zip".to_vec()),
        kind: ArchiveKindSpec::Zip,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"first.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"second.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE1C);
}

#[test]
fn archive_gzip_invalid_name_uses_gunzip_path() {
    let archive_cfg = base_archive_config();

    let (payload, span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"invalid-name.gz".to_vec()),
        kind: ArchiveKindSpec::Gzip,
        entries: vec![ArchiveEntrySpec {
            name_bytes: vec![0xFF, 0xFE, 0xFD],
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE1D);
}

#[test]
fn archive_directory_entry_name_not_scanned() {
    let archive_cfg = base_archive_config();

    let (payload, span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"dir-entries.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"SIM0_AB12_dir".to_vec(),
                payload: Vec::new(),
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::Directory,
            },
            ArchiveEntrySpec {
                name_bytes: b"real.txt".to_vec(),
                payload,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(1, span)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE1E);
}

struct NestedArchiveCase {
    outer_spec: ArchiveFileSpec,
    outer_bytes: Vec<u8>,
    outer_entry_paths: Vec<Vec<u8>>,
    inner_entry_paths: Vec<Vec<u8>>,
    inner_bytes: Vec<u8>,
}

/// Archive-specific expected-secret metadata.
struct ExpectedSpec {
    entry_idx: usize,
    span: SpanU32,
    disposition: ExpectedDisposition,
}

impl ExpectedSpec {
    fn must_find(entry_idx: usize, span: SpanU32) -> Self {
        Self {
            entry_idx,
            span,
            disposition: ExpectedDisposition::MustFind,
        }
    }
}

fn base_archive_config() -> ArchiveConfig {
    ArchiveConfig {
        enabled: true,
        ..ArchiveConfig::default()
    }
}

/// Build a minimal single-rule suite for archive tests.
fn archive_rule_suite() -> RuleSuiteSpec {
    RuleSuiteSpec {
        schema_version: SCHEMA_VERSION,
        rules: vec![SyntheticRuleSpec {
            rule_id: 0,
            name: "archive_rule_0".to_string(),
            anchors: vec![b"SIM0_".to_vec()],
            radius: 32,
            regex: "SIM0_[A-Z0-9]{4}".to_string(),
        }],
    }
}

fn build_archive_scenario(
    archive_cfg: &ArchiveConfig,
    spec: ArchiveFileSpec,
    expected_specs: Vec<ExpectedSpec>,
) -> Scenario {
    let (bytes, entry_paths) =
        materialize_archive_with_paths(&spec, archive_cfg).expect("materialize archive");

    let mut expected = Vec::with_capacity(expected_specs.len());
    for exp in expected_specs {
        // Entry expectations are expressed by entry order, then mapped to the
        // canonicalized virtual path produced by the materializer.
        let path_bytes = entry_paths.get(exp.entry_idx).expect("entry path").clone();
        expected.push(ExpectedSecret {
            path: SimPath::new(path_bytes),
            rule_id: 0,
            root_span: exp.span,
            repr: SecretRepr::Raw,
            disposition: exp.disposition,
        });
    }

    Scenario {
        schema_version: SCHEMA_VERSION,
        fs: SimFsSpec {
            nodes: vec![SimNodeSpec::File {
                path: spec.root_path.clone(),
                contents: bytes,
                discovery_len_hint: None,
                type_hint: SimTypeHint::File,
            }],
        },
        rule_suite: archive_rule_suite(),
        expected,
        archives: vec![spec],
    }
}

fn build_scenario_with_archives(
    archive_files: Vec<(ArchiveFileSpec, Vec<u8>)>,
    expected: Vec<ExpectedSecret>,
) -> Scenario {
    let mut nodes = Vec::with_capacity(archive_files.len());
    let mut archives = Vec::with_capacity(archive_files.len());

    for (spec, bytes) in archive_files {
        nodes.push(SimNodeSpec::File {
            path: spec.root_path.clone(),
            contents: bytes,
            discovery_len_hint: None,
            type_hint: SimTypeHint::File,
        });
        archives.push(spec);
    }

    Scenario {
        schema_version: SCHEMA_VERSION,
        fs: SimFsSpec { nodes },
        rule_suite: archive_rule_suite(),
        expected,
        archives,
    }
}

/// Build a nested archive specimen plus expected paths for the outer entry and
/// inner entries (relative to the outer entry display path).
fn build_nested_archive_case(
    archive_cfg: &ArchiveConfig,
    outer_root: &[u8],
    outer_kind: ArchiveKindSpec,
    outer_entry_name: &[u8],
    inner_kind: ArchiveKindSpec,
    inner_entries: Vec<ArchiveEntrySpec>,
) -> NestedArchiveCase {
    let inner_spec = ArchiveFileSpec {
        root_path: SimPath::new(b"inner.tmp".to_vec()),
        kind: inner_kind,
        entries: inner_entries.clone(),
        corruption: None,
    };
    let inner_materialized = materialize_archive(&inner_spec).expect("materialize inner archive");

    let outer_spec = ArchiveFileSpec {
        root_path: SimPath::new(outer_root.to_vec()),
        kind: outer_kind,
        entries: vec![ArchiveEntrySpec {
            name_bytes: outer_entry_name.to_vec(),
            payload: inner_materialized.bytes.clone(),
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let (outer_bytes, outer_paths) =
        materialize_archive_with_paths(&outer_spec, archive_cfg).expect("materialize outer");

    let inner_path_spec = ArchiveFileSpec {
        root_path: SimPath::new(outer_paths[0].clone()),
        kind: inner_kind,
        entries: inner_entries,
        corruption: None,
    };
    let inner_paths =
        entry_paths(&inner_path_spec, &inner_materialized, archive_cfg).expect("inner paths");

    NestedArchiveCase {
        outer_spec,
        outer_bytes,
        outer_entry_paths: outer_paths,
        inner_entry_paths: inner_paths,
        inner_bytes: inner_materialized.bytes,
    }
}

fn payload_with_secret(prefix: usize, suffix: usize) -> (Vec<u8>, SpanU32) {
    let mut buf = vec![b'x'; prefix];
    let start = buf.len() as u32;
    buf.extend_from_slice(SECRET_PRIMARY);
    let end = buf.len() as u32;
    buf.extend(std::iter::repeat_n(b'x', suffix));
    (buf, SpanU32::new(start, end))
}

fn payload_with_two_secrets(
    first_prefix: usize,
    between: usize,
    suffix: usize,
) -> (Vec<u8>, SpanU32, SpanU32) {
    let mut buf = vec![b'x'; first_prefix];
    let first_start = buf.len() as u32;
    buf.extend_from_slice(SECRET_PRIMARY);
    let first_end = buf.len() as u32;
    buf.extend(std::iter::repeat_n(b'x', between));
    let second_start = buf.len() as u32;
    buf.extend_from_slice(SECRET_SECONDARY);
    let second_end = buf.len() as u32;
    buf.extend(std::iter::repeat_n(b'x', suffix));
    (
        buf,
        SpanU32::new(first_start, first_end),
        SpanU32::new(second_start, second_end),
    )
}

fn span_for_pattern(haystack: &[u8], needle: &[u8]) -> SpanU32 {
    let idx = haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("pattern not found");
    SpanU32::new(idx as u32, (idx + needle.len()) as u32)
}

fn component_cap_name(components: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for idx in 0..components {
        if idx > 0 {
            out.push(b'/');
        }
        out.push(b'a');
    }
    out
}

fn run_archive_scenario(scenario: Scenario, archive_cfg: ArchiveConfig, seed: u64) {
    run_archive_scenario_inner(scenario, archive_cfg, seed, None);
}

fn run_archive_scenario_with_countdown(
    scenario: Scenario,
    archive_cfg: ArchiveConfig,
    seed: u64,
    countdown: u32,
) {
    run_archive_scenario_inner(scenario, archive_cfg, seed, Some(countdown));
}

fn run_archive_scenario_inner(
    scenario: Scenario,
    archive_cfg: ArchiveConfig,
    seed: u64,
    countdown: Option<u32>,
) {
    let mut run_cfg = RunConfig {
        workers: 1,
        chunk_size: 64,
        overlap: 64,
        max_in_flight_objects: 4,
        buffer_pool_cap: 4,
        max_file_size: u64::MAX,
        max_steps: 0,
        max_transform_depth: 2,
        scan_utf16_variants: true,
        archive: archive_cfg,
        stability_runs: 1,
        archive_deadline_countdown: countdown,
    };

    let engine = build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine");
    let required = engine.required_overlap() as u32;
    if run_cfg.overlap < required {
        run_cfg.overlap = required;
    }
    if run_cfg.chunk_size < run_cfg.overlap {
        run_cfg.chunk_size = run_cfg.overlap;
    }

    let runner = ScannerSimRunner::new(run_cfg, seed);
    let fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    match runner.run(&scenario, &engine, &fault_plan) {
        RunOutcome::Ok { .. } => {}
        RunOutcome::Failed(fail) => {
            panic!("archive corpus sim failed: {fail:?}");
        }
    }
}

/// Deterministic wall-clock timeout: the countdown fires after entry 0 is
/// fully scanned but before entry 1 starts.  Entry 0 contains a secret that
/// must be found; entries 1 and 2 (which also contains a secret) are never
/// processed.
///
/// The countdown value (2) accounts for two `is_deadline_expired()` calls
/// during entry 0: one at the outer-loop top and one per inner read-loop
/// iteration (payload fits in a single chunk).  The third call — the
/// outer-loop check for entry 1 — fires the timeout.
///
/// This exercises the full sim pipeline: archive scan → partial outcome →
/// ground-truth oracle validates that only entry 0's secret is reported.
#[test]
fn archive_wall_clock_timeout_skips_later_entries() {
    let archive_cfg = base_archive_config();

    let (payload_a, span_a) = payload_with_secret(2, 9);
    let (payload_b, _span_b) = payload_with_secret(2, 9);
    let filler = vec![b'x'; 20];

    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"timeout.tar".to_vec()),
        kind: ArchiveKindSpec::Tar,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"first.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"filler.txt".to_vec(),
                payload: filler,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"third.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    // Only entry 0's secret must be found — the timeout prevents entry 2.
    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario_with_countdown(scenario, archive_cfg, 0xC0FF_EE20, 2);
}

/// Same as `archive_wall_clock_timeout_skips_later_entries` but for zip
/// format.  Zip scan calls `is_deadline_expired()` at the outer loop top
/// and inside the decompression read loop.  The countdown fires before
/// entry 1 starts, so only entry 0's secret is found.
#[test]
fn archive_zip_wall_clock_timeout_skips_later_entries() {
    let archive_cfg = base_archive_config();

    let (payload_a, span_a) = payload_with_secret(2, 9);
    let (payload_b, _span_b) = payload_with_secret(2, 9);
    let filler = vec![b'x'; 20];

    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"timeout.zip".to_vec()),
        kind: ArchiveKindSpec::Zip,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"first.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"filler.txt".to_vec(),
                payload: filler,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"third.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario_with_countdown(scenario, archive_cfg, 0xC0FF_EE21, 2);
}

/// Same for tar.gz (gzip-compressed tar).  The gzip outer scan calls
/// `is_deadline_expired()` twice (outer + inner read), then the tar
/// nested scan inherits the countdown state.  With a small payload and
/// countdown=2, the timeout fires after the first tar entry is fully
/// delivered through the gzip→tar pipeline.
#[test]
fn archive_targz_wall_clock_timeout_skips_later_entries() {
    let archive_cfg = base_archive_config();

    let (payload_a, span_a) = payload_with_secret(2, 9);
    let (payload_b, _span_b) = payload_with_secret(2, 9);
    let filler = vec![b'x'; 20];

    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"timeout.tar.gz".to_vec()),
        kind: ArchiveKindSpec::TarGz,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"first.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"filler.txt".to_vec(),
                payload: filler,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"third.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    // tar.gz has extra deadline checks from the gzip decompression layer,
    // so the countdown needs to be higher to reach the tar inner scan.
    // Use a generous value that fires after the first entry completes.
    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario_with_countdown(scenario, archive_cfg, 0xC0FF_EE22, 2);
}

/// Same for tar.bz2 (bzip2-compressed tar). With deterministic countdown=2,
/// the timeout fires before the third entry and only entry 0 is expected.
#[test]
fn archive_tarbz2_wall_clock_timeout_skips_later_entries() {
    let archive_cfg = base_archive_config();

    let (payload_a, span_a) = payload_with_secret(2, 9);
    let (payload_b, _span_b) = payload_with_secret(2, 9);
    let filler = vec![b'x'; 20];

    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"timeout.tar.bz2".to_vec()),
        kind: ArchiveKindSpec::TarBz2,
        entries: vec![
            ArchiveEntrySpec {
                name_bytes: b"first.txt".to_vec(),
                payload: payload_a,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"filler.txt".to_vec(),
                payload: filler,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
            ArchiveEntrySpec {
                name_bytes: b"third.txt".to_vec(),
                payload: payload_b,
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            },
        ],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span_a)]);
    run_archive_scenario_with_countdown(scenario, archive_cfg, 0xC0FF_EE23, 2);
}

/// Truncated `.tar.bz2` must not panic and must not surface findings for
/// entries that were never fully decompressed.
#[test]
fn archive_tarbz2_truncated_archive_is_handled() {
    let archive_cfg = base_archive_config();

    let (payload, _span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"truncated.tar.bz2".to_vec()),
        kind: ArchiveKindSpec::TarBz2,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"inner.txt".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: Some(ArchiveCorruptionSpec::TruncateTo { len: 8 }),
    };

    let scenario = build_archive_scenario(&archive_cfg, spec, Vec::new());
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE24);
}

/// Truncated standalone `.bz2` must not panic and must not surface findings
/// for entries that were never fully decompressed.
#[test]
fn archive_bzip2_truncated_is_handled() {
    let archive_cfg = base_archive_config();

    let (payload, _span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"truncated.bz2".to_vec()),
        kind: ArchiveKindSpec::Bzip2,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"<bunzip2>".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: Some(ArchiveCorruptionSpec::TruncateTo { len: 8 }),
    };

    let scenario = build_archive_scenario(&archive_cfg, spec, Vec::new());
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE27);
}

/// Standalone `.bz2` smoke test: exercises the `scan_bzip2_stream()` path
/// with a single payload containing a detectable secret.
#[test]
fn archive_bzip2_smoke() {
    let archive_cfg = base_archive_config();

    let (payload, span) = payload_with_secret(4, 4);
    let spec = ArchiveFileSpec {
        root_path: SimPath::new(b"smoke.bz2".to_vec()),
        kind: ArchiveKindSpec::Bzip2,
        entries: vec![ArchiveEntrySpec {
            name_bytes: b"<bunzip2>".to_vec(),
            payload,
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        }],
        corruption: None,
    };

    let scenario =
        build_archive_scenario(&archive_cfg, spec, vec![ExpectedSpec::must_find(0, span)]);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE25);
}

/// Nested bzip2-in-tar: a `.bz2` file as an entry inside a `.tar`,
/// exercising the `ArchiveKind::Bzip2` nesting branch in `local_fs_tar.rs`.
#[test]
fn archive_nested_bzip2_in_tar() {
    let archive_cfg = base_archive_config();

    let (payload, span) = payload_with_secret(4, 4);
    let inner_entries = vec![ArchiveEntrySpec {
        name_bytes: b"<bunzip2>".to_vec(),
        payload,
        compression: EntryCompressionSpec::Store,
        encrypted: false,
        kind: EntryKindSpec::RegularFile,
    }];

    let nested = build_nested_archive_case(
        &archive_cfg,
        b"outer.tar",
        ArchiveKindSpec::Tar,
        b"inner.bz2",
        ArchiveKindSpec::Bzip2,
        inner_entries,
    );

    let expected = vec![ExpectedSecret {
        path: SimPath::new(nested.inner_entry_paths[0].clone()),
        rule_id: 0,
        root_span: span,
        repr: SecretRepr::Raw,
        disposition: ExpectedDisposition::MustFind,
    }];

    let scenario =
        build_scenario_with_archives(vec![(nested.outer_spec, nested.outer_bytes)], expected);
    run_archive_scenario(scenario, archive_cfg, 0xC0FF_EE26);
}
