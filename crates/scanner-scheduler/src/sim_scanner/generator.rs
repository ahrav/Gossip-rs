//! Synthetic scenario generator for scanner simulations.
//!
//! The generator produces deterministic filesystem contents (including archives)
//! with known secrets and an accompanying rule suite that should detect only
//! those secrets. It is intended for differential + ground-truth oracles in
//! the sim harness.
//!
//! Invariants:
//! - Rule prefixes are ASCII and included in anchors; regexes match `prefix + tail`.
//! - Noise bytes are lowercase `x` to avoid accidental prefix matches.
//! - `ExpectedSecret.root_span` refers to the encoded bytes within the file's content buffer.
//! - Archive entry spans refer to uncompressed entry payload bytes.
//! - Gzip/bzip2 scenarios are generated with exactly one entry so expected-path
//!   cardinality matches the scanner's single-stream model.

use regex::bytes::Regex;

use crate::api::{
    AnchorPolicy, Gate, RuleSpec, TransformConfig, TransformId, TransformMode, Tuning,
    ValidatorKind,
};
use crate::archive::ArchiveConfig;
use crate::sim::fs::{SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
use crate::sim::mutation::{encode_secret, TOKEN_ALPHABET};
use crate::sim::rng::SimRng;
use crate::sim_archive::{entry_paths, materialize_archive};
use crate::sim_scanner::scenario::{
    ArchiveEntrySpec, ArchiveFileSpec, ArchiveKindSpec, EntryCompressionSpec, EntryKindSpec,
    ExpectedDisposition, ExpectedSecret, RuleSuiteSpec, RunConfig, Scenario, SecretRepr, SpanU32,
    SyntheticRuleSpec,
};
use crate::Engine;

const DEFAULT_SCHEMA_VERSION: u32 = 1;

/// Configuration for generating synthetic scanner scenarios.
#[derive(Clone, Debug)]
pub struct ScenarioGenConfig {
    /// Scenario schema version to stamp on outputs.
    pub schema_version: u32,
    /// Number of synthetic rules to generate.
    pub rule_count: u32,
    /// Number of files to generate.
    pub file_count: u32,
    /// Number of secrets inserted per file or archive entry.
    pub secrets_per_file: u32,
    /// Length of the random token tail appended to each rule prefix.
    pub token_len: u32,
    /// Minimum number of noise bytes between and around secrets.
    pub min_noise_len: u32,
    /// Maximum number of noise bytes between and around secrets.
    pub max_noise_len: u32,
    /// Allowed secret representations to choose from.
    pub representations: Vec<SecretRepr>,
    /// Number of archive files to generate.
    pub archive_count: u32,
    /// Number of entries per archive file.
    pub archive_entries: u32,
    /// Allowed archive kinds to choose from.
    pub archive_kinds: Vec<ArchiveKindSpec>,
    /// Archive config used to compute virtual paths for expected secrets.
    pub archive: ArchiveConfig,
}

impl Default for ScenarioGenConfig {
    fn default() -> Self {
        Self {
            schema_version: DEFAULT_SCHEMA_VERSION,
            rule_count: 2,
            file_count: 2,
            secrets_per_file: 3,
            token_len: 12,
            min_noise_len: 8,
            max_noise_len: 32,
            representations: vec![
                SecretRepr::Raw,
                SecretRepr::Base64,
                SecretRepr::UrlPercent,
                SecretRepr::Utf16Le,
                SecretRepr::Utf16Be,
            ],
            archive_count: 0,
            archive_entries: 2,
            archive_kinds: vec![
                ArchiveKindSpec::Tar,
                ArchiveKindSpec::TarGz,
                ArchiveKindSpec::TarBz2,
                ArchiveKindSpec::Zip,
                ArchiveKindSpec::Gzip,
                ArchiveKindSpec::Bzip2,
            ],
            archive: ArchiveConfig::default(),
        }
    }
}

impl ScenarioGenConfig {
    /// Validate configuration invariants, returning a human-readable error.
    fn validate(&self) -> Result<(), String> {
        if self.rule_count == 0 {
            return Err("rule_count must be > 0".to_string());
        }
        if self.file_count == 0 && self.archive_count == 0 {
            return Err("file_count or archive_count must be > 0".to_string());
        }
        if self.token_len == 0 {
            return Err("token_len must be > 0".to_string());
        }
        if self.min_noise_len > self.max_noise_len {
            return Err("min_noise_len must be <= max_noise_len".to_string());
        }
        if self.representations.is_empty() {
            return Err("representations must be non-empty".to_string());
        }
        if self.archive_count > 0 && self.archive_entries == 0 {
            return Err("archive_entries must be > 0 when archive_count > 0".to_string());
        }
        Ok(())
    }
}

/// Generate a deterministic scenario and rule suite from a seed.
///
/// The returned `ExpectedSecret` spans refer to the encoded payload inserted
/// into each file/entry payload, not the decoded representation.
/// Archive expected paths are derived via `sim_archive::entry_paths`, which
/// mirrors production canonicalization and locator formatting.
pub fn generate_scenario(seed: u64, cfg: &ScenarioGenConfig) -> Result<Scenario, String> {
    cfg.validate()?;

    let mut rng = SimRng::new(seed);
    let rule_suite = build_rule_suite(cfg);

    let total_files = cfg.file_count.saturating_add(cfg.archive_count);
    let mut nodes = Vec::with_capacity(total_files as usize);
    let mut expected =
        Vec::with_capacity((cfg.file_count.saturating_mul(cfg.secrets_per_file)) as usize);
    let mut archives = Vec::with_capacity(cfg.archive_count as usize);

    for file_idx in 0..cfg.file_count {
        let path = SimPath::new(format!("file_{file_idx}.txt").into_bytes());
        let mut buf = Vec::new();

        for _ in 0..cfg.secrets_per_file {
            append_noise(&mut rng, cfg, &mut buf);

            let rule_id = rng.gen_range(0, cfg.rule_count);
            let repr = pick_repr(&mut rng, &cfg.representations);
            let token = make_token(rule_id, cfg.token_len, &mut rng);
            let encoded = encode_secret(&token, &repr);

            let start = buf.len() as u32;
            buf.extend_from_slice(&encoded);
            let end = buf.len() as u32;

            expected.push(ExpectedSecret {
                path: path.clone(),
                rule_id,
                root_span: SpanU32::new(start, end),
                repr,
                disposition: ExpectedDisposition::MustFind,
            });
        }

        append_noise(&mut rng, cfg, &mut buf);
        nodes.push(SimNodeSpec::File {
            path,
            contents: buf,
            // Generator defaults to a known file type; tests override as needed.
            discovery_len_hint: None,
            type_hint: SimTypeHint::File,
        });
    }

    if cfg.archive_count > 0 {
        let kinds = effective_archive_kinds(cfg);
        for archive_idx in 0..cfg.archive_count {
            let kind = pick_archive_kind(&mut rng, &kinds);
            let root_path = SimPath::new(format_archive_name(archive_idx, kind).into_bytes());
            // Gzip/bzip2 are modeled as single logical entries in the scanner,
            // so we generate exactly one entry to keep oracle cardinality exact.
            let entries_per_archive =
                if matches!(kind, ArchiveKindSpec::Gzip | ArchiveKindSpec::Bzip2) {
                    1
                } else {
                    cfg.archive_entries
                };

            let mut entries = Vec::with_capacity(entries_per_archive as usize);
            let mut pending = Vec::new();

            for entry_idx in 0..entries_per_archive {
                let name_bytes = format!("entry_{archive_idx}_{entry_idx}.txt").into_bytes();
                let mut payload = Vec::new();

                for _ in 0..cfg.secrets_per_file {
                    append_noise(&mut rng, cfg, &mut payload);

                    let rule_id = rng.gen_range(0, cfg.rule_count);
                    let repr = pick_repr(&mut rng, &cfg.representations);
                    let token = make_token(rule_id, cfg.token_len, &mut rng);
                    let encoded = encode_secret(&token, &repr);

                    let start = payload.len() as u32;
                    payload.extend_from_slice(&encoded);
                    let end = payload.len() as u32;

                    pending.push(PendingExpected {
                        entry_idx,
                        rule_id,
                        span: SpanU32::new(start, end),
                        repr,
                    });
                }

                append_noise(&mut rng, cfg, &mut payload);

                let compression = match kind {
                    ArchiveKindSpec::Zip => {
                        if rng.gen_bool(1, 2) {
                            EntryCompressionSpec::Deflate
                        } else {
                            EntryCompressionSpec::Store
                        }
                    }
                    _ => EntryCompressionSpec::Store,
                };

                entries.push(ArchiveEntrySpec {
                    name_bytes,
                    payload,
                    compression,
                    encrypted: false,
                    kind: EntryKindSpec::RegularFile,
                });
            }

            let spec = ArchiveFileSpec {
                root_path: root_path.clone(),
                kind,
                entries,
                corruption: None,
            };

            let materialized =
                materialize_archive(&spec).map_err(|e| format!("archive build failed: {e}"))?;
            let entry_paths = entry_paths(&spec, &materialized, &cfg.archive)
                .map_err(|e| format!("archive entry path computation failed: {e}"))?;

            for item in pending {
                let path_bytes = entry_paths
                    .get(item.entry_idx as usize)
                    .ok_or_else(|| "missing archive entry path".to_string())?;
                let disposition = disposition_for_entry(&spec, item.entry_idx)?;
                expected.push(ExpectedSecret {
                    path: SimPath::new(path_bytes.clone()),
                    rule_id: item.rule_id,
                    root_span: item.span,
                    repr: item.repr,
                    disposition,
                });
            }

            nodes.push(SimNodeSpec::File {
                path: root_path,
                contents: materialized.bytes,
                discovery_len_hint: None,
                type_hint: SimTypeHint::File,
            });
            archives.push(spec);
        }
    }

    Ok(Scenario {
        schema_version: cfg.schema_version,
        fs: SimFsSpec { nodes },
        rule_suite,
        expected,
        archives,
    })
}

#[derive(Clone, Debug)]
struct PendingExpected {
    entry_idx: u32,
    rule_id: u32,
    span: SpanU32,
    repr: SecretRepr,
}

fn effective_archive_kinds(cfg: &ScenarioGenConfig) -> Vec<ArchiveKindSpec> {
    if cfg.archive_kinds.is_empty() {
        vec![
            ArchiveKindSpec::Tar,
            ArchiveKindSpec::TarGz,
            ArchiveKindSpec::TarBz2,
            ArchiveKindSpec::Zip,
            ArchiveKindSpec::Gzip,
            ArchiveKindSpec::Bzip2,
        ]
    } else {
        cfg.archive_kinds.clone()
    }
}

fn pick_archive_kind(rng: &mut SimRng, kinds: &[ArchiveKindSpec]) -> ArchiveKindSpec {
    let idx = if kinds.len() <= 1 {
        0
    } else {
        rng.gen_range(0, kinds.len() as u32) as usize
    };
    kinds[idx]
}

fn format_archive_name(idx: u32, kind: ArchiveKindSpec) -> String {
    match kind {
        ArchiveKindSpec::Gzip => format!("archive_{idx}.gz"),
        ArchiveKindSpec::Bzip2 => format!("archive_{idx}.bz2"),
        ArchiveKindSpec::Tar => format!("archive_{idx}.tar"),
        ArchiveKindSpec::TarGz => format!("archive_{idx}.tar.gz"),
        ArchiveKindSpec::TarBz2 => format!("archive_{idx}.tar.bz2"),
        ArchiveKindSpec::Zip => format!("archive_{idx}.zip"),
    }
}

/// Classify whether a generated secret is mandatory or best-effort.
///
/// This keeps oracle failures actionable: deterministic generation defects
/// should fail hard, while expected scanner limitations (encryption,
/// non-regular entries, intentional corruption) are marked `MayMiss`.
fn disposition_for_entry(
    spec: &ArchiveFileSpec,
    entry_idx: u32,
) -> Result<ExpectedDisposition, String> {
    let entry = spec
        .entries
        .get(entry_idx as usize)
        .ok_or_else(|| "missing archive entry".to_string())?;

    if entry.encrypted {
        return Ok(ExpectedDisposition::MayMiss {
            reason: "encrypted entry".to_string(),
        });
    }
    if entry.kind != EntryKindSpec::RegularFile {
        return Ok(ExpectedDisposition::MayMiss {
            reason: "non-regular entry".to_string(),
        });
    }
    if spec.corruption.is_some() {
        return Ok(ExpectedDisposition::MayMiss {
            reason: "archive corruption".to_string(),
        });
    }
    Ok(ExpectedDisposition::MustFind)
}

/// Build a deterministic engine from a synthetic rule suite.
///
/// This leaks rule names and anchors to obtain `'static` lifetimes and should
/// be used only in test harnesses or short-lived simulations.
pub fn build_engine_from_suite(
    suite: &RuleSuiteSpec,
    run_cfg: &RunConfig,
) -> Result<Engine, String> {
    let rules = materialize_rules(suite)?;
    let transforms = synthetic_transforms();
    let tuning = synthetic_tuning(run_cfg);
    Ok(Engine::new_with_anchor_policy(
        rules,
        transforms,
        tuning,
        AnchorPolicy::ManualOnly,
    ))
}

/// Convert a rule suite spec into engine rule specs.
///
/// This leaks the anchors and names to satisfy the engine's `'static` lifetime
/// requirements for `RuleSpec`.
pub fn materialize_rules(suite: &RuleSuiteSpec) -> Result<Vec<RuleSpec>, String> {
    let mut rules = Vec::with_capacity(suite.rules.len());
    for spec in &suite.rules {
        let name: &'static str = Box::leak(spec.name.clone().into_boxed_str());
        let mut anchors = Vec::with_capacity(spec.anchors.len());
        for anchor in &spec.anchors {
            let leaked: &'static [u8] = Box::leak(anchor.clone().into_boxed_slice());
            anchors.push(leaked);
        }
        let anchors: &'static [&'static [u8]] = Box::leak(anchors.into_boxed_slice());
        let re =
            Regex::new(&spec.regex).map_err(|e| format!("rule {} regex error: {e}", spec.name))?;

        rules.push(RuleSpec {
            name,
            anchors,
            radius: spec.radius as usize,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: None,
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re,
        });
    }
    Ok(rules)
}

/// Transforms suitable for synthetic scenarios.
pub fn synthetic_transforms() -> Vec<TransformConfig> {
    vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ]
}

/// Tuning defaults for synthetic scenarios derived from the run config.
pub fn synthetic_tuning(run_cfg: &RunConfig) -> Tuning {
    let mut tuning = crate::demo::demo_tuning();
    tuning.max_transform_depth = run_cfg.max_transform_depth as usize;
    tuning.scan_utf16_variants = run_cfg.scan_utf16_variants;
    tuning
}

/// Build a deterministic rule suite with fixed prefixes and regex shapes.
///
/// Radius covers `prefix + token` plus a small slack (8 bytes) to avoid
/// boundary misses in synthetic data.
fn build_rule_suite(cfg: &ScenarioGenConfig) -> RuleSuiteSpec {
    let mut rules = Vec::with_capacity(cfg.rule_count as usize);
    for rule_id in 0..cfg.rule_count {
        let prefix = rule_prefix(rule_id);
        let regex = format!("{prefix}[A-Z0-9]{{{}}}", cfg.token_len);
        let radius = prefix
            .len()
            .saturating_add(cfg.token_len as usize)
            .saturating_add(8);
        rules.push(SyntheticRuleSpec {
            rule_id,
            name: format!("sim_rule_{rule_id}"),
            anchors: vec![prefix.as_bytes().to_vec()],
            radius: radius as u32,
            regex,
        });
    }

    RuleSuiteSpec {
        schema_version: cfg.schema_version,
        rules,
    }
}

fn rule_prefix(rule_id: u32) -> String {
    format!("SIM{rule_id}_")
}

fn make_token(rule_id: u32, token_len: u32, rng: &mut SimRng) -> Vec<u8> {
    let prefix = rule_prefix(rule_id);
    let mut out = Vec::with_capacity(prefix.len() + token_len as usize);
    out.extend_from_slice(prefix.as_bytes());
    for _ in 0..token_len {
        let idx = rng.gen_range(0, TOKEN_ALPHABET.len() as u32) as usize;
        out.push(TOKEN_ALPHABET[idx]);
    }
    out
}

fn pick_repr(rng: &mut SimRng, reprs: &[SecretRepr]) -> SecretRepr {
    let idx = rng.gen_range(0, reprs.len() as u32) as usize;
    reprs[idx].clone()
}

fn append_noise(rng: &mut SimRng, cfg: &ScenarioGenConfig, buf: &mut Vec<u8>) {
    let noise_len = if cfg.min_noise_len == cfg.max_noise_len {
        cfg.min_noise_len
    } else {
        rng.gen_range(cfg.min_noise_len, cfg.max_noise_len + 1)
    };
    // Use lowercase filler to avoid matching uppercase rule prefixes.
    buf.resize(buf.len().saturating_add(noise_len as usize), b'x');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_generation_is_deterministic() {
        let cfg = ScenarioGenConfig::default();
        let a = generate_scenario(42, &cfg).expect("scenario a");
        let b = generate_scenario(42, &cfg).expect("scenario b");
        assert_eq!(a.expected.len(), b.expected.len());
        assert_eq!(a.fs.nodes.len(), b.fs.nodes.len());
        assert_eq!(a.rule_suite.rules.len(), b.rule_suite.rules.len());
        assert_eq!(a.archives.len(), b.archives.len());
    }
}
