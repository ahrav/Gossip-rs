use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct TraitCoverageAudit {
    trait_name: &'static str,
    real_impls: &'static [&'static str],
    test_stubs: &'static [&'static str],
}

const TRAIT_COVERAGE_AUDIT: &[TraitCoverageAudit] = &[
    TraitCoverageAudit {
        trait_name: "CacheSlot",
        real_impls: &["DeltaSlot", "TreeSlot"],
        test_stubs: &["TestSlot"],
    },
    TraitCoverageAudit {
        trait_name: "CandidateSink",
        real_impls: &[
            "CandidateBuffer",
            "PackCandidateCollector",
            "SpillCandidateSink",
        ],
        test_stubs: &["AbortOnFirstEmit"],
    },
    TraitCoverageAudit {
        trait_name: "CommitGraph",
        real_impls: &["CommitGraphMem", "SimCommitGraph"],
        test_stubs: &["MockGraph", "SmallTestGraph", "StubCommitGraph"],
    },
    TraitCoverageAudit {
        trait_name: "EventSink",
        real_impls: &["NullEventSink", "VecEventSink"],
        test_stubs: &["BlockingCommitMetaSink", "CapturingFindingSink"],
    },
    TraitCoverageAudit {
        trait_name: "ExternalBaseProvider",
        real_impls: &["PackIo", "SimPackIo"],
        test_stubs: &[
            "ExternalBaseProviderImpl",
            "FailingExternalBase",
            "MissingExternalBase",
            "NoExternal",
        ],
    },
    TraitCoverageAudit {
        trait_name: "GitEventOutput",
        real_impls: &["NullEventSink", "VecEventSink"],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "OidResolver",
        real_impls: &["MidxView"],
        test_stubs: &["NullResolver"],
    },
    TraitCoverageAudit {
        trait_name: "PackCandidateSink",
        real_impls: &["CappedPackCandidateSink", "CollectingPackCandidateSink"],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "PackObjectSink",
        real_impls: &["EngineAdapter"],
        test_stubs: &[
            "CollectingSink",
            "ErrorOnFinishSink",
            "ErrorSink",
            "TestSink",
        ],
    },
    TraitCoverageAudit {
        trait_name: "PackReader",
        real_impls: &["BytesView", "SlicePackReader"],
        test_stubs: &["FaultyPackReader"],
    },
    TraitCoverageAudit {
        trait_name: "PersistenceStore",
        real_impls: &[
            "InMemoryPersistenceStore",
            "RocksDbStore",
            "SimPersistStore",
        ],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "RefWatermarkStore",
        real_impls: &["RocksDbStore", "SimStartSet"],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "RepoError",
        real_impls: &["PreflightError", "RepoOpenError"],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "RepoLimits",
        real_impls: &["PreflightLimits", "RepoOpenLimits"],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "ScanCheckpointSink",
        real_impls: &["NoopCheckpointSink"],
        test_stubs: &["AbortingSink"],
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
    },
    TraitCoverageAudit {
        trait_name: "SeenBlobStore",
        real_impls: &[
            "AlwaysSeenStore",
            "HybridSeenStore",
            "InMemoryPersistenceStore",
            "InMemorySeenStore",
            "NeverSeenStore",
            "RocksDbStore",
            "RoaringSeenStore",
        ],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "StartSetResolver",
        real_impls: &["NativeRefResolver", "SimStartSet"],
        test_stubs: &[],
    },
    TraitCoverageAudit {
        trait_name: "TreeSource",
        real_impls: &["ObjectStore", "SimTreeSource"],
        test_stubs: &["MockTreeSource", "NeverLoadTreeSource"],
    },
    TraitCoverageAudit {
        trait_name: "UniqueBlobSink",
        real_impls: &["CollectingUniqueBlobSink", "MappingBridge"],
        test_stubs: &[],
    },
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source dir") {
        let entry = entry.expect("read dir entry");
        let path = entry.path();
        if entry.file_type().expect("read file type").is_dir() {
            collect_rs_files(&path, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Advances past a `<...>` block handling nested angle brackets.
/// Returns the remainder of the string after the closing `>`, or `None` if
/// the input does not start with `<` or the brackets are unbalanced.
fn skip_angle_brackets(s: &str) -> Option<&str> {
    if !s.starts_with('<') {
        return None;
    }
    let mut depth = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[i + 1..]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Strips path prefix and generics from a type or trait name.
///
/// Generics are stripped first so that path separators inside type parameters
/// (e.g., `Option<std::io::Error>`) do not confuse the path resolution.
///
/// `super::repo::RepoError` becomes `RepoError`.
/// `MappingBridge<'_, S>` becomes `MappingBridge`.
/// `Option<std::io::Error>` becomes `Option`.
fn extract_bare_name(raw: &str) -> String {
    let base = raw.split(['<', '{', '(']).next().unwrap_or(raw);
    base.rsplit("::").next().unwrap_or(base).to_owned()
}

/// Parses a trimmed line starting with `impl` into `(trait_name, type_name)`.
///
/// Handles optional generic params (`impl<S: Foo> Trait for Type`), path-
/// qualified names, and lifetime-elided types. Returns `None` for inherent
/// impls (no `for` keyword) and blanket impls where the implementing type
/// is a single uppercase letter (e.g., `T`).
fn parse_impl_for(trimmed: &str) -> Option<(String, String)> {
    let rest = trimmed.strip_prefix("impl")?;
    let rest = rest.trim_start();

    // Skip optional generic params: impl<...> ...
    let rest = if rest.starts_with('<') {
        skip_angle_brackets(rest)?.trim_start()
    } else {
        rest
    };

    // Find `for` keyword to split trait from type.
    let for_pos = rest.find(" for ")?;
    let trait_raw = &rest[..for_pos].trim();
    let after_for = rest[for_pos + 5..].trim_start();

    // Extract the type name (first token, possibly with generics).
    let type_end = after_for
        .find(|c: char| c.is_whitespace() || c == '{')
        .unwrap_or(after_for.len());
    let type_raw = &after_for[..type_end];

    let trait_name = extract_bare_name(trait_raw);
    let type_name = extract_bare_name(type_raw);

    // Skip blanket impls where the type is a single uppercase letter.
    if type_name.len() == 1
        && type_name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_uppercase())
    {
        return None;
    }

    Some((trait_name, type_name))
}

/// Scans all `.rs` files under `dir` for `impl Trait for Type` lines.
///
/// Returns a set of `(trait_name, type_name)` pairs with path prefixes
/// and generics stripped. Line and block comments are skipped.
///
/// Assumes each `impl ... for ...` appears on a single line — multi-line
/// declarations where `for` lands on a continuation line are not detected.
/// `cargo fmt` keeps these single-line in practice.
fn collect_impl_pairs(dir: &Path) -> HashSet<(String, String)> {
    let mut files = Vec::new();
    collect_rs_files(dir, &mut files);

    let mut pairs = HashSet::new();
    for path in &files {
        let source = fs::read_to_string(path).unwrap();
        let mut in_block_comment = false;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if in_block_comment {
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }
            if trimmed.starts_with("/*") {
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if !trimmed.starts_with("impl") {
                continue;
            }
            if let Some(pair) = parse_impl_for(trimmed) {
                pairs.insert(pair);
            }
        }
    }
    pairs
}

fn collect_public_trait_names(dir: &Path) -> Vec<String> {
    let mut files = Vec::new();
    collect_rs_files(dir, &mut files);
    files.sort();

    let mut names = Vec::new();
    for path in files {
        let source = fs::read_to_string(path).unwrap();
        let mut in_block_comment = false;
        for line in source.lines() {
            let trimmed = line.trim_start();
            if in_block_comment {
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }
            if trimmed.starts_with("/*") {
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            let is_pub_trait = trimmed.starts_with("pub trait ")
                || trimmed.starts_with("pub(crate) trait ")
                || trimmed.starts_with("pub(super) trait ")
                || trimmed.starts_with("pub unsafe trait ")
                || trimmed.starts_with("pub(crate) unsafe trait ")
                || trimmed.starts_with("pub(super) unsafe trait ");
            if !is_pub_trait {
                continue;
            }
            // For all visibility forms the trait name is the token after `trait`.
            let Some(trait_pos) = trimmed.find("trait ") else {
                continue;
            };
            let after_trait = trimmed[trait_pos + 6..].trim_start();
            let Some(raw_name) = after_trait.split_whitespace().next() else {
                continue;
            };
            let name = extract_bare_name(raw_name.trim_end_matches([':']));
            names.push(name);
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
    assert_eq!(
        audited_traits, public_traits,
        "TRAIT_COVERAGE_AUDIT is out of date. If you added or removed a `pub trait`, \
         update the table in src/trait_coverage_audit_tests.rs to match.",
    );
}

#[test]
fn trait_coverage_audit_has_real_impl_coverage_for_every_entry() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let impl_pairs = collect_impl_pairs(&src_dir);

    // Traits with blanket impls where the implementing type is a generic
    // parameter (e.g., `impl<T> EventSink for T where T: GitEventOutput`).
    // These cannot be matched by explicit `impl Trait for Type` lines, so
    // we fall back to checking that the type implements the prerequisite trait.
    let blanket_impl_requirements: &[(&str, &str)] = &[("EventSink", "GitEventOutput")];

    let mut errors = Vec::new();

    for entry in TRAIT_COVERAGE_AUDIT {
        for impl_name in entry.real_impls.iter().chain(entry.test_stubs.iter()) {
            let pair = (entry.trait_name.to_owned(), (*impl_name).to_owned());
            if impl_pairs.contains(&pair) {
                continue;
            }
            // Blanket impl fallback: verify the type implements the
            // prerequisite trait that the blanket impl requires.
            if let Some(&(_, required_trait)) = blanket_impl_requirements
                .iter()
                .find(|&&(trait_name, _)| trait_name == entry.trait_name)
            {
                let required_pair = (required_trait.to_owned(), (*impl_name).to_owned());
                if impl_pairs.contains(&required_pair) {
                    continue;
                }
            }
            errors.push(format!(
                "  {} for {} — not found in src/",
                entry.trait_name, impl_name
            ));
        }
    }

    if !errors.is_empty() {
        panic!(
            "TRAIT_COVERAGE_AUDIT has {} impl(s) not found in source:\n{}",
            errors.len(),
            errors.join("\n")
        );
    }
}

#[test]
fn trait_coverage_audit_catches_unlisted_impls() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let impl_pairs = collect_impl_pairs(&src_dir);

    let blanket_impl_requirements: &[(&str, &str)] = &[("EventSink", "GitEventOutput")];

    // Build lookup: trait_name -> set of (real_impls ∪ test_stubs).
    let mut listed: HashMap<&str, HashSet<&str>> = HashMap::new();
    for entry in TRAIT_COVERAGE_AUDIT {
        let set = listed.entry(entry.trait_name).or_default();
        for name in entry.real_impls.iter().chain(entry.test_stubs.iter()) {
            set.insert(name);
        }
    }

    let mut errors = Vec::new();

    for (trait_name, type_name) in &impl_pairs {
        let Some(known) = listed.get(trait_name.as_str()) else {
            // Trait not in audit table — the forward test
            // (`trait_coverage_audit_matches_public_trait_set`) already catches this.
            continue;
        };
        if known.contains(type_name.as_str()) {
            continue;
        }
        // Blanket impl fallback: the type satisfies the trait through a blanket
        // impl via the prerequisite trait, so it would not appear as an explicit
        // entry in the table.
        if let Some(&(_, required_trait)) = blanket_impl_requirements
            .iter()
            .find(|&&(t, _)| t == trait_name.as_str())
        {
            let required_pair = (required_trait.to_owned(), type_name.clone());
            if impl_pairs.contains(&required_pair) {
                continue;
            }
        }
        errors.push(format!(
            "  {} for {} — found in source but not in TRAIT_COVERAGE_AUDIT",
            trait_name, type_name
        ));
    }

    errors.sort();

    if !errors.is_empty() {
        panic!(
            "Source contains {} impl(s) not listed in TRAIT_COVERAGE_AUDIT:\n{}\n\
             Add missing types to the `real_impls` or `test_stubs` arrays.",
            errors.len(),
            errors.join("\n")
        );
    }
}
