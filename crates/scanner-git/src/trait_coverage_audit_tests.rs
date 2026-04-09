use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct TraitCoverageAudit {
    trait_name: &'static str,
    real_impls: &'static [&'static str],
    test_stubs: &'static [&'static str],
    min_real_impl_tests: usize,
}

const TRAIT_COVERAGE_AUDIT: &[TraitCoverageAudit] = &[
    TraitCoverageAudit {
        trait_name: "CandidateSink",
        real_impls: &[
            "CandidateBuffer",
            "PackCandidateCollector",
            "SpillCandidateSink",
        ],
        test_stubs: &["AbortOnFirstEmit"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "CommitGraph",
        real_impls: &["CommitGraphMem", "SimCommitGraph"],
        test_stubs: &["MockGraph", "SmallTestGraph", "StubCommitGraph"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "EventSink",
        real_impls: &[
            "blanket impl for GitEventOutput",
            "NullEventSink",
            "VecEventSink",
        ],
        test_stubs: &["BlockingCommitMetaSink", "CapturingFindingSink"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "ExternalBaseProvider",
        real_impls: &["PackIo", "SimPackIo"],
        test_stubs: &["ExternalBaseProviderImpl", "NoExternal", "NoExternalBases"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "GitEventOutput",
        real_impls: &["NullEventSink", "VecEventSink"],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "OidResolver",
        real_impls: &["MidxView"],
        test_stubs: &["NoopResolver"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "PackCandidateSink",
        real_impls: &["CappedPackCandidateSink", "CollectingPackCandidateSink"],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "PackObjectSink",
        real_impls: &["EngineAdapter"],
        test_stubs: &["CollectingSink", "NullSink", "TestSink"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "PackReader",
        real_impls: &["BytesView", "SlicePackReader"],
        test_stubs: &["FaultyPackReader"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "PersistenceStore",
        real_impls: &[
            "InMemoryPersistenceStore",
            "RocksDbStore",
            "SimPersistStore",
        ],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "RefWatermarkStore",
        real_impls: &["RocksDbStore", "SimStartSet"],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "RepoError",
        real_impls: &["PreflightError", "RepoOpenError"],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "RepoLimits",
        real_impls: &["PreflightLimits", "RepoOpenLimits"],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "ScanCheckpointSink",
        real_impls: &["NoopCheckpointSink"],
        test_stubs: &["AbortingSink"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "SeenBitmapPersister",
        real_impls: &[
            "InMemoryPersistenceStore",
            "NullSeenBitmapPersister",
            "RocksDbStore",
            "SimPersistStore",
        ],
        test_stubs: &["FailingSeenBitmapPersister"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "SeenBlobStore",
        real_impls: &[
            "AlwaysSeenStore",
            "InMemoryPersistenceStore",
            "InMemorySeenStore",
            "NeverSeenStore",
            "RocksDbStore",
            "RoaringSeenStore",
        ],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "StartSetResolver",
        real_impls: &["NativeRefResolver", "SimStartSet"],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "TreeSource",
        real_impls: &["ObjectStore", "SimTreeSource"],
        test_stubs: &["MockTreeSource", "NeverLoadTreeSource"],
        min_real_impl_tests: 1,
    },
    TraitCoverageAudit {
        trait_name: "UniqueBlobSink",
        real_impls: &["CollectingUniqueBlobSink", "MappingBridge"],
        test_stubs: &[],
        min_real_impl_tests: 1,
    },
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn collect_public_trait_names(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect_rs_files(dir, &mut files);
    files.sort();

    let mut names = Vec::new();
    for path in files {
        let source = fs::read_to_string(path).unwrap();
        for line in source.lines() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("pub trait ") {
                continue;
            }
            let Some(raw_name) = trimmed.split_whitespace().nth(2) else {
                continue;
            };
            let name = raw_name.trim_end_matches([':', '{']);
            names.push(name.to_owned());
        }
    }

    names.sort();
    names
}

#[test]
fn trait_coverage_audit_matches_public_trait_set() {
    let mut audited_traits = TRAIT_COVERAGE_AUDIT
        .iter()
        .map(|entry| entry.trait_name.to_owned())
        .collect::<Vec<_>>();
    audited_traits.sort();

    let public_traits =
        collect_public_trait_names(Path::new(env!("CARGO_MANIFEST_DIR")).join("src").as_path());
    assert_eq!(audited_traits, public_traits);
}

#[test]
fn trait_coverage_audit_has_real_impl_coverage_for_every_entry() {
    for entry in TRAIT_COVERAGE_AUDIT {
        assert!(
            !entry.real_impls.is_empty(),
            "{} must list at least one real implementation",
            entry.trait_name
        );
        assert!(
            entry.min_real_impl_tests >= 1,
            "{} must cite at least one real-implementation test",
            entry.trait_name
        );
        let _ = entry.test_stubs;
    }
}
