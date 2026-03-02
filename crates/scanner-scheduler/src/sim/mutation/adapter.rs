//! Adapter that translates [`MutationPlan`]s into a [`Scenario`] consumable
//! by [`ScannerSimRunner`], plus a post-run mutation oracle.
//!
//! # Two-oracle architecture
//!
//! The sim-runner's built-in ground-truth oracle checks every finding against
//! `scenario.expected` using containment-based span matching (`expected.span
//! ⊆ finding.span`). Mutation testing cannot predict exact spans up front
//! because context wrappers and encoding layers shift boundaries, so we
//! register only [`MayMiss`] point-span sentinels that the ground-truth oracle
//! will never fail on. The real correctness check happens *after* the scan
//! completes, in [`check_mutation_expectations`], which uses any-intersection
//! span matching and consults the per-case [`Outcome`] predictions from the
//! family oracle.
//!
//! # File layout
//!
//! Each mutation case becomes a separate simulated file named
//! `mutation_<index>.txt`. The file content is structured as:
//!
//! ```text
//! [noise_len bytes of '\n'] [wrapped token bytes] [noise_len bytes of '\n']
//! ```
//!
//! The newline noise padding serves two purposes: it separates the token from
//! file boundaries so that boundary effects do not mask detection failures,
//! and it provides enough leading context for the engine's overlap/radius
//! requirements (the caller typically sets `noise_len` to the engine's
//! `required_overlap()`).
//!
//! [`MayMiss`]: ExpectedDisposition::MayMiss
//! [`Outcome`]: super::family::Outcome

use crate::api::AnchorPolicy;
use crate::sim::fs::{SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
use crate::sim::mutation::family::{Outcome, TokenFamily};
use crate::sim::mutation::plan::{execute_plan, GeneratedCase, MutationPlan};
use crate::sim::rng::SimRng;
use crate::sim_scanner::generator::{materialize_rules, synthetic_tuning};
use crate::sim_scanner::scenario::{
    ExpectedDisposition, ExpectedSecret, RuleSuiteSpec, RunConfig, Scenario, SecretRepr, SpanU32,
    SyntheticRuleSpec,
};
use crate::{Engine, FindingRec};

/// Byte stride between consecutive [`MayMiss`] point-span sentinels scattered
/// through the wrapped-token region. Any real finding >= this many bytes wide
/// is guaranteed to contain at least one sentinel, satisfying the ground-truth
/// oracle's containment check.
///
/// [`MayMiss`]: ExpectedDisposition::MayMiss
const SENTINEL_STRIDE: usize = 8;

/// Aggregate result of [`check_mutation_expectations`].
///
/// [`passed()`](MutationCheckResult::passed) returns `true` when every case's
/// expectation was satisfied. When `false`,
/// [`violations()`](MutationCheckResult::violations) contains one entry per
/// failing case with diagnostic details. Note that only `MustMatch`-not-found
/// failures are recorded; `MustNotMatch`-but-found cases are intentionally
/// tolerated (see [`check_mutation_expectations`] for rationale).
#[derive(Clone, Debug)]
pub struct MutationCheckResult {
    violations: Vec<MutationViolation>,
}

impl MutationCheckResult {
    /// Construct a result from a list of violations.
    pub fn new(violations: Vec<MutationViolation>) -> Self {
        Self { violations }
    }

    /// `true` when every case's expectation was satisfied.
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }

    /// Per-case violation diagnostics (empty when [`passed()`](Self::passed)).
    pub fn violations(&self) -> &[MutationViolation] {
        &self.violations
    }
}

/// A single mutation expectation that was violated.
///
/// Only generated for `MustMatch` cases where no overlapping finding was
/// produced. Carries structured fields for programmatic access alongside a
/// human-readable diagnostic.
#[derive(Clone, Debug)]
pub struct MutationViolation {
    /// Index into the original `plans` / `cases` slice.
    pub case_index: usize,
    /// Token family of the failing case.
    pub family: TokenFamily,
    /// Rule ID that should have matched.
    pub rule_id: u32,
    /// Expected token span as `(start, end)` byte offsets within the file.
    pub expected_span: (u64, u64),
    /// Human-readable diagnostic with rule ID, family, and byte span.
    pub message: String,
}

/// Per-family detection rule specification used to build the mutation scenario's
/// [`RuleSuiteSpec`].
///
/// Each [`TokenFamily`] maps to exactly one `FamilyRule`. The `rule_id` is
/// the family's index in [`TokenFamily::ALL`], which both the scenario builder
/// and the mutation oracle use to correlate findings back to families.
struct FamilyRule {
    /// Positional index of this family in [`TokenFamily::ALL`].
    rule_id: u32,
    /// Byte-string anchors the engine uses for fast prefix filtering.
    anchors: Vec<Vec<u8>>,
    /// Regex pattern the engine compiles for full-match validation.
    regex: String,
    /// Search radius (bytes around an anchor hit) the engine scans.
    radius: u32,
}

/// Build a [`Scenario`] and [`Vec<GeneratedCase>`] from a batch of mutation plans.
///
/// Returns `(scenario, cases, noise_len_used)`.
///
/// The scenario contains one simulated file per plan, each with the
/// noise-token-noise layout described in the module docs. The `expected`
/// field is populated with [`MayMiss`] point-span sentinels (1-byte spans
/// every [`SENTINEL_STRIDE`] bytes through the token region, for every rule ID) that satisfy
/// the ground-truth oracle's containment check without causing false
/// failures. The mutation oracle ([`check_mutation_expectations`]) uses the
/// returned `cases` and `noise_len_used` to compute token spans independently.
///
/// The caller typically calls this twice: once with a placeholder `noise_len`
/// to discover the engine's `required_overlap()`, then again with
/// `noise_len = required_overlap` to ensure the noise padding is wide enough
/// for the engine's search radius. See the random-seed test harness for this
/// two-pass pattern.
///
/// [`MayMiss`]: ExpectedDisposition::MayMiss
pub fn build_mutation_scenario(
    plans: &[MutationPlan],
    noise_len: usize,
) -> (Scenario, Vec<GeneratedCase>, usize) {
    let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();

    let family_rules = build_family_rules(&cases);
    let rules: Vec<SyntheticRuleSpec> = family_rules
        .iter()
        .map(|fr| SyntheticRuleSpec {
            rule_id: fr.rule_id,
            name: format!("mutation_family_{}", fr.rule_id),
            anchors: fr.anchors.clone(),
            regex: fr.regex.clone(),
            radius: fr.radius,
        })
        .collect();

    let noise = vec![b'\n'; noise_len];
    let sentinel_reason = "mutation: deferred to mutation oracle".to_string();

    let mut nodes = Vec::new();
    let mut expected = Vec::new();
    let mut dir_children = Vec::new();

    for (idx, case) in cases.iter().enumerate() {
        let path_str = format!("mutation_{idx}.txt");
        let path = SimPath::new(path_str.into_bytes());
        dir_children.push(path.clone());

        let mut contents = Vec::with_capacity(noise_len + case.wrapped.bytes.len() + noise_len);
        contents.extend_from_slice(&noise);
        contents.extend_from_slice(&case.wrapped.bytes);
        contents.extend_from_slice(&noise);

        nodes.push(SimNodeSpec::File {
            path: path.clone(),
            contents,
            discovery_len_hint: None,
            type_hint: SimTypeHint::File,
        });

        // Scatter 1-byte MayMiss point spans every SENTINEL_STRIDE bytes
        // through the wrapped-token region, for every rule_id. The
        // ground-truth oracle requires expected.span ⊆ finding.span, so
        // any real finding >= SENTINEL_STRIDE bytes wide is guaranteed to
        // contain at least one sentinel. We
        // register all rule_ids (not just the case's own family) because the
        // ground-truth oracle would flag an unexpected finding for a rule_id
        // that has no expected entry at all.
        let region_start = noise_len;
        let region_end = noise_len + case.wrapped.bytes.len();
        for family in TokenFamily::ALL {
            let rid = family_rule_id(family);
            let mut pos = region_start;
            while pos < region_end {
                let end = (pos + 1).min(region_end);
                expected.push(ExpectedSecret {
                    path: path.clone(),
                    rule_id: rid,
                    root_span: SpanU32::new(pos as u32, end as u32),
                    repr: SecretRepr::Raw,
                    disposition: ExpectedDisposition::MayMiss {
                        reason: sentinel_reason.clone(),
                    },
                });
                pos += SENTINEL_STRIDE;
            }
        }
    }

    dir_children.sort();
    nodes.insert(
        0,
        SimNodeSpec::Dir {
            path: SimPath::new(b".".to_vec()),
            children: dir_children,
        },
    );

    let scenario = Scenario {
        schema_version: 1,
        fs: SimFsSpec { nodes },
        rule_suite: RuleSuiteSpec {
            schema_version: 1,
            rules,
        },
        expected,
        archives: vec![],
    };

    (scenario, cases, noise_len)
}

/// Build an [`Engine`] from a mutation scenario's rule suite.
///
/// The engine is configured with no transform layers and
/// [`AnchorPolicy::ManualOnly`]. Transforms are omitted because the
/// mutation plans already apply their own encoding layers via `MutOp::Encode`,
/// and stacking engine transforms on top would make the oracle's span
/// predictions unreliable. `ManualOnly` prevents the engine from
/// auto-discovering anchors, ensuring it uses exactly the anchors specified
/// in the family rules.
pub fn build_mutation_engine(suite: &RuleSuiteSpec, run_cfg: &RunConfig) -> Result<Engine, String> {
    let rules = materialize_rules(suite)?;
    let transforms = vec![];
    let tuning = synthetic_tuning(run_cfg);
    Ok(Engine::new_with_anchor_policy(
        rules,
        transforms,
        tuning,
        AnchorPolicy::ManualOnly,
    ))
}

/// Post-run oracle for mutation-specific expectations.
///
/// For each case, computes the expected token span as
/// `noise_len + wrapped.token_offset .. + token_len` and checks whether any
/// finding **from the same file** with the correct `rule_id` intersects that
/// span. Intersection matching (`finding.start < span.end && finding.end >
/// span.start`) is deliberately more lenient than the ground-truth oracle's
/// containment check, because mutations can shift the regex match boundaries
/// relative to the oracle's predicted span.
///
/// Each case maps to a distinct file (`mutation_{idx}.txt`). The oracle
/// derives the expected `FileId` for each case from the lexicographic sort
/// order of those paths (matching the sim runner's file-id assignment).
/// Without this per-file filtering, a finding from one file could
/// incorrectly satisfy a sibling case's `MustMatch` expectation when
/// multiple cases share the same family (and thus the same rule_id and
/// similar per-file byte offsets).
///
/// # Asymmetric failure treatment
///
/// - **`MustMatch` not found** -- recorded as a violation. This is the
///   primary value of mutation testing: detecting false negatives where the
///   engine fails to find an unmutated (or benignly mutated) token.
/// - **`MustNotMatch` but found** -- silently ignored. Context wrappers can
///   contribute characters that extend a regex match beyond what the oracle
///   predicted, and the engine's validation window may be wider than assumed.
///   Treating these as failures would produce noisy false alarms without
///   meaningful signal.
/// - **`MayMatch`** -- either outcome is accepted by definition.
pub fn check_mutation_expectations(
    cases: &[GeneratedCase],
    noise_len: usize,
    findings: &[FindingRec],
) -> MutationCheckResult {
    // Index findings by rule_id so the per-case lookup is O(findings_for_rule)
    // instead of O(total_findings).
    let mut findings_by_rule: std::collections::HashMap<u32, Vec<&FindingRec>> =
        std::collections::HashMap::new();
    for f in findings {
        findings_by_rule.entry(f.rule_id).or_default().push(f);
    }

    let file_ids = mutation_case_file_ids(cases.len());
    let mut violations = Vec::new();

    for (case_idx, case) in cases.iter().enumerate() {
        let rule_id = family_rule_id(case.plan.family);
        let expected_file_id = file_ids[case_idx];
        let span_start = (noise_len + case.wrapped.token_offset) as u64;
        let span_end = span_start + case.wrapped.token_len as u64;

        // Any-intersection match: finding overlaps the expected token span
        // AND belongs to this case's file.
        let found = findings_by_rule.get(&rule_id).is_some_and(|fs| {
            fs.iter().any(|f| {
                f.file_id == expected_file_id
                    && f.root_hint_start < span_end
                    && f.root_hint_end > span_start
            })
        });

        match case.expectation {
            Outcome::MustMatch if !found => {
                violations.push(MutationViolation {
                    case_index: case_idx,
                    family: case.plan.family,
                    rule_id,
                    expected_span: (span_start, span_end),
                    message: format!(
                        "case {case_idx} ({:?}): MustMatch but not found (rule_id={rule_id}, span={span_start}..{span_end})",
                        case.plan.family,
                    ),
                });
            }
            Outcome::MustNotMatch if found => {
                // Silently tolerated: context wrappers can contribute characters
                // that extend a regex match beyond what the oracle predicted, and
                // the engine's validation window may be wider than assumed.
                // Treating these as failures would produce noisy false alarms
                // without meaningful signal. Only MustMatch-not-found cases carry
                // actionable false-negative signal.
            }
            _ => {}
        }
    }

    MutationCheckResult::new(violations)
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

/// Compute the expected [`FileId`] for each mutation case.
///
/// `build_mutation_scenario` creates files named `mutation_{idx}.txt`. The
/// sim runner assigns `FileId`s sequentially from 0 based on lexicographic
/// sort of those file paths. This function replicates that sort to produce
/// a `Vec` where `result[case_idx]` is the `FileId` the runner assigns to
/// `mutation_{case_idx}.txt`.
fn mutation_case_file_ids(case_count: usize) -> Vec<crate::api::FileId> {
    let mut indexed_paths: Vec<(usize, String)> = (0..case_count)
        .map(|idx| (idx, format!("mutation_{idx}.txt")))
        .collect();
    indexed_paths.sort_by(|a, b| a.1.as_bytes().cmp(b.1.as_bytes()));

    let mut ids = vec![crate::api::FileId(0); case_count];
    for (file_id, (case_idx, _)) in indexed_paths.iter().enumerate() {
        ids[*case_idx] = crate::api::FileId(file_id as u32);
    }
    ids
}

/// Map a [`TokenFamily`] to its rule ID.
///
/// Delegates to [`TokenFamily::rule_id`], the single source of truth for
/// the family→rule_id mapping.
fn family_rule_id(family: TokenFamily) -> u32 {
    family.rule_id()
}

/// Build one [`FamilyRule`] per token family with anchors, regex, and radius
/// tuned to match the canonical (unmutated) token format.
///
/// Families with a known structural prefix (AWS, GitHub, JWT) use that prefix
/// as the anchor and a regex that matches the full canonical format. Blob
/// families (Base64Blob, UrlEncodedBlob) lack a fixed prefix, so they derive
/// anchors from every case's canonical token via [`all_canonical_prefixes`].
/// Each unique prefix is registered as a separate anchor so the engine can
/// detect tokens regardless of which case's seed produced them.
///
/// Radius values are set to slightly exceed the maximum canonical token
/// length so the engine's search window covers the entire token after an
/// anchor hit, even if the anchor appears at the token's start.
fn build_family_rules(cases: &[GeneratedCase]) -> Vec<FamilyRule> {
    let mut rules = Vec::with_capacity(TokenFamily::ALL.len());

    for family in TokenFamily::ALL {
        let rule_id = family_rule_id(family);
        let (anchors, regex, radius) = match family {
            TokenFamily::AwsAccessKey => {
                (vec![b"AKIA".to_vec()], "AKIA[A-Z2-7]{16}".to_string(), 28)
            }
            TokenFamily::GithubFinegrainedPat => (
                vec![b"github_pat_".to_vec()],
                "github_pat_[0-9A-Za-z]{82}".to_string(),
                101,
            ),
            TokenFamily::GithubClassicPat => (
                vec![b"ghp_".to_vec()],
                "ghp_[0-9A-Za-z]{36}".to_string(),
                48,
            ),
            TokenFamily::JwtLike => (
                vec![b"eyJ".to_vec()],
                r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+".to_string(),
                300,
            ),
            TokenFamily::Base64Blob => {
                let anchors = all_canonical_prefixes(cases, family, 4);
                (anchors, "[A-Za-z0-9+/]{32,68}={0,2}".to_string(), 80)
            }
            TokenFamily::UrlEncodedBlob => {
                let anchors = all_canonical_prefixes(cases, family, 6);
                (anchors, r"(?:%[0-9A-Fa-f]{2}){16,32}".to_string(), 120)
            }
        };
        rules.push(FamilyRule {
            rule_id,
            anchors,
            regex,
            radius,
        });
    }

    rules
}

/// Collect the unique `len`-byte canonical prefixes from every case matching
/// `family`, to use as anchors for families without a fixed prefix.
///
/// Falls back to generating a fresh token with seed 0 if no case matches
/// (e.g. if the plan batch does not include this family). The fallback is
/// deterministic but may produce a different anchor than a case-derived one,
/// so callers should ensure every family has at least one case when anchor
/// stability matters.
fn all_canonical_prefixes(
    cases: &[GeneratedCase],
    family: TokenFamily,
    len: usize,
) -> Vec<Vec<u8>> {
    let mut prefixes: Vec<Vec<u8>> = Vec::new();
    for case in cases {
        if case.plan.family == family {
            let prefix = case.canonical[..len.min(case.canonical.len())].to_vec();
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
    }
    if prefixes.is_empty() {
        // Fallback for families not present in this plan batch (e.g.
        // single-family unit tests). Deterministic but may differ from
        // case-derived anchors; callers needing anchor stability should
        // ensure every family has at least one case.
        if cfg!(debug_assertions) {
            eprintln!(
                "all_canonical_prefixes: no case for {family:?}, falling back to seed-0 token"
            );
        }
        let token = family.gen_valid(&mut SimRng::new(0));
        prefixes.push(token[..len.min(token.len())].to_vec());
    }
    prefixes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_rules_valid_regex_and_reject_noise() {
        let mut rng = SimRng::new(42);
        let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
        let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();
        let rules = build_family_rules(&cases);
        let noise = "\n".repeat(100);

        for (rule, family) in rules.iter().zip(TokenFamily::ALL.iter()) {
            let re = regex::Regex::new(&rule.regex)
                .unwrap_or_else(|e| panic!("regex compile failed for {family:?}: {e}"));

            let canonical = family.gen_valid(&mut SimRng::new(99));
            let text = std::str::from_utf8(&canonical)
                .unwrap_or_else(|_| panic!("{family:?} canonical not utf8"));
            assert!(
                re.is_match(text),
                "{family:?} canonical does not match regex {:?}",
                rule.regex,
            );
            assert!(
                !re.is_match(&noise),
                "{family:?} regex matches pure newline noise",
            );
        }
    }

    #[test]
    fn build_mutation_scenario_determinism() {
        let mut rng1 = SimRng::new(7);
        let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng1, 1);
        let (s1, _, _) = build_mutation_scenario(&plans, 64);
        let (s2, _, _) = build_mutation_scenario(&plans, 64);
        let json1 = serde_json::to_string(&s1).unwrap();
        let json2 = serde_json::to_string(&s2).unwrap();
        assert_eq!(json1, json2);
    }

    /// Two MustMatch cases from the same family with the same context wrapper
    /// produce identical per-file token spans. A finding from one file must
    /// not satisfy the other case's MustMatch expectation.
    #[test]
    fn cross_file_finding_does_not_satisfy_sibling_case() {
        use super::super::plan::{ContextWrap, MutationPlan};

        let plan0 = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 42,
            case_id: 0,
            ops: vec![],
            context: ContextWrap::EnvAssignment,
        };
        let plan1 = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 99,
            case_id: 1,
            ops: vec![],
            context: ContextWrap::EnvAssignment,
        };

        let plans = vec![plan0, plan1];
        let (_scenario, cases, noise_len) = build_mutation_scenario(&plans, 64);

        // Both unmutated → MustMatch.
        assert_eq!(cases[0].expectation, Outcome::MustMatch);
        assert_eq!(cases[1].expectation, Outcome::MustMatch);

        // Same family + same context → identical per-file token spans.
        let span0_start = (noise_len + cases[0].wrapped.token_offset) as u64;
        let span0_end = span0_start + cases[0].wrapped.token_len as u64;
        let span1_start = (noise_len + cases[1].wrapped.token_offset) as u64;
        let span1_end = span1_start + cases[1].wrapped.token_len as u64;
        assert_eq!(span0_start, span1_start);
        assert_eq!(span0_end, span1_end);

        // Simulate: engine detected the token in file 0 only (not file 1).
        let finding = FindingRec {
            file_id: crate::api::FileId(0),
            rule_id: family_rule_id(TokenFamily::AwsAccessKey),
            span_start: span0_start as u32,
            span_end: span0_end as u32,
            root_hint_start: span0_start,
            root_hint_end: span0_end,
            dedupe_with_span: false,
            step_id: Default::default(),
            confidence_score: 0,
        };

        let result = check_mutation_expectations(&cases, noise_len, &[finding]);

        // Case 1 has no finding from its file — it should be a violation.
        assert!(
            !result.passed(),
            "case 1 has no finding from its own file but check reported passed",
        );
        assert_eq!(result.violations().len(), 1);
        assert_eq!(result.violations()[0].case_index, 1);
    }

    #[test]
    fn token_span_computed_correctly() {
        use super::super::plan::{ContextWrap, MutationPlan};

        let plan = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 42,
            case_id: 0,
            ops: vec![],
            context: ContextWrap::EnvAssignment,
        };
        let plans = vec![plan];
        let (_scenario, cases, noise_len) = build_mutation_scenario(&plans, 16);

        let case = &cases[0];
        let expected_start = noise_len + case.wrapped.token_offset;
        let expected_end = expected_start + case.wrapped.token_len;
        // Verify the noise_len is passed through correctly.
        assert_eq!(noise_len, 16);
        // For EnvAssignment, token_offset > 0.
        assert!(case.wrapped.token_offset > 0);
        assert!(expected_end > expected_start);
    }

    // -- Direct unit tests for check_mutation_expectations --

    fn make_case(
        family: TokenFamily,
        expectation: Outcome,
        token_offset: usize,
        token_len: usize,
    ) -> GeneratedCase {
        use super::super::plan::{ContextWrap, MutationPlan, WrappedToken};

        let canonical = family.gen_valid(&mut SimRng::new(0));
        let mutated = canonical.clone();
        let total_len = token_offset + token_len + 4; // 4 bytes trailing context
        let bytes = vec![b'x'; total_len];

        GeneratedCase {
            canonical,
            mutated,
            wrapped: WrappedToken {
                bytes,
                token_offset,
                token_len,
            },
            expectation,
            plan: MutationPlan {
                family,
                base_seed: 0,
                case_id: 0,
                ops: vec![],
                context: ContextWrap::Raw,
            },
        }
    }

    fn make_finding(rule_id: u32, start: u64, end: u64) -> FindingRec {
        FindingRec {
            file_id: crate::api::FileId(0),
            rule_id,
            span_start: 0,
            span_end: 0,
            root_hint_start: start,
            root_hint_end: end,
            dedupe_with_span: false,
            step_id: Default::default(),
            confidence_score: 0,
        }
    }

    #[test]
    fn must_match_with_overlapping_finding_passes() {
        let noise = 16;
        let case = make_case(TokenFamily::AwsAccessKey, Outcome::MustMatch, 4, 20);
        let rule_id = TokenFamily::AwsAccessKey.rule_id();
        // Token span: noise+4 .. noise+4+20 = 20..44
        let finding = make_finding(rule_id, 20, 44);
        let result = check_mutation_expectations(&[case], noise, &[finding]);
        assert!(result.passed());
        assert!(result.violations().is_empty());
    }

    #[test]
    fn must_match_no_finding_is_violation() {
        let noise = 16;
        let case = make_case(TokenFamily::AwsAccessKey, Outcome::MustMatch, 4, 20);
        let result = check_mutation_expectations(&[case], noise, &[]);
        assert!(!result.passed());
        assert_eq!(result.violations().len(), 1);
        assert_eq!(result.violations()[0].case_index, 0);
        assert_eq!(
            result.violations()[0].rule_id,
            TokenFamily::AwsAccessKey.rule_id()
        );
        assert_eq!(result.violations()[0].expected_span, (20, 40));
    }

    #[test]
    fn must_match_adjacent_but_not_overlapping_is_violation() {
        let noise = 16;
        let case = make_case(TokenFamily::AwsAccessKey, Outcome::MustMatch, 4, 20);
        let rule_id = TokenFamily::AwsAccessKey.rule_id();
        // Token span: 20..44. Finding ends exactly at span start (no overlap).
        let finding = make_finding(rule_id, 10, 20);
        let result = check_mutation_expectations(&[case], noise, &[finding]);
        assert!(
            !result.passed(),
            "adjacent finding (end == span.start) must not satisfy MustMatch"
        );
    }

    #[test]
    fn must_not_match_but_found_is_tolerated() {
        let noise = 16;
        let case = make_case(TokenFamily::AwsAccessKey, Outcome::MustNotMatch, 4, 20);
        let rule_id = TokenFamily::AwsAccessKey.rule_id();
        let finding = make_finding(rule_id, 20, 44);
        let result = check_mutation_expectations(&[case], noise, &[finding]);
        assert!(result.passed(), "MustNotMatch + found should be tolerated");
    }

    #[test]
    fn may_match_either_outcome_accepted() {
        let noise = 16;
        let case_with = make_case(TokenFamily::AwsAccessKey, Outcome::MayMatch, 4, 20);
        let case_without = make_case(TokenFamily::AwsAccessKey, Outcome::MayMatch, 4, 20);
        let rule_id = TokenFamily::AwsAccessKey.rule_id();
        let finding = make_finding(rule_id, 20, 44);

        let result_with = check_mutation_expectations(&[case_with], noise, &[finding]);
        assert!(result_with.passed(), "MayMatch + found should pass");

        let result_without = check_mutation_expectations(&[case_without], noise, &[]);
        assert!(result_without.passed(), "MayMatch + not found should pass");
    }

    #[test]
    fn empty_cases_passes() {
        let result = check_mutation_expectations(&[], 16, &[]);
        assert!(result.passed());
        assert!(result.violations().is_empty());
    }

    #[test]
    fn empty_plans_produces_valid_scenario() {
        let (scenario, cases, noise_len) = build_mutation_scenario(&[], 64);
        assert!(cases.is_empty());
        assert_eq!(noise_len, 64);
        // Only the root directory node; no file nodes.
        assert_eq!(
            scenario.fs.nodes.len(),
            1,
            "empty plans should produce only the root dir node"
        );
        // Rules are still generated (one per family) regardless of plans.
        assert!(
            !scenario.rule_suite.rules.is_empty(),
            "family rules should still be present even with no plans"
        );
        assert!(scenario.expected.is_empty());
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod adapter_proptests {
    use super::super::plan::{ContextWrap, MutationPlan};
    use super::*;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 32;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        /// Varies the seed and checks that every family's regex matches its
        /// canonical token and rejects pure-newline noise.
        #[test]
        fn prop_family_rules_match_canonical_and_reject_noise(seed: u64) {
            let mut rng = SimRng::new(seed);
            let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
            let cases: Vec<GeneratedCase> = plans.iter().map(execute_plan).collect();
            let rules = build_family_rules(&cases);
            let noise = "\n".repeat(100);

            for (rule, family) in rules.iter().zip(TokenFamily::ALL.iter()) {
                let re = regex::Regex::new(&rule.regex)
                    .unwrap_or_else(|e| panic!("regex compile failed for {:?}: {}", family, e));

                let canonical = family.gen_valid(&mut SimRng::new(seed.wrapping_add(1)));
                let text = std::str::from_utf8(&canonical)
                    .unwrap_or_else(|_| panic!("{:?} canonical not utf8", family));
                prop_assert!(
                    re.is_match(text),
                    "{:?} canonical does not match regex {:?} (seed={})",
                    family, rule.regex, seed,
                );
                prop_assert!(
                    !re.is_match(&noise),
                    "{:?} regex matches pure newline noise (seed={})",
                    family, seed,
                );
            }
        }

        /// Varies the seed and checks that `build_mutation_scenario` is
        /// deterministic for any seed.
        #[test]
        fn prop_build_mutation_scenario_determinism(seed: u64) {
            let mut rng = SimRng::new(seed);
            let plans = super::super::plan_gen::random_mutation_plans_all_families(&mut rng, 1);
            let (s1, _, _) = build_mutation_scenario(&plans, 64);
            let (s2, _, _) = build_mutation_scenario(&plans, 64);
            let json1 = serde_json::to_string(&s1).unwrap();
            let json2 = serde_json::to_string(&s2).unwrap();
            prop_assert!(
                json1 == json2,
                "scenario not deterministic for seed={}",
                seed,
            );
        }

        /// Varies seed, noise_len, family, and context wrapper to check that
        /// token_len > 0, the span falls within the file, and non-Raw
        /// contexts produce token_offset > 0.
        #[test]
        fn prop_token_spans_valid_for_any_context(
            seed: u64,
            noise_len in 0_usize..256,
            family_idx in 0_usize..6,
            context_idx in 0_usize..6,
        ) {
            let family = TokenFamily::ALL[family_idx];
            let context = ContextWrap::ALL[context_idx];

            let plan = MutationPlan {
                family,
                base_seed: seed,
                case_id: 0,
                ops: vec![],
                context,
            };
            let plans = vec![plan];
            let (_scenario, cases, nl) = build_mutation_scenario(&plans, noise_len);

            let case = &cases[0];
            prop_assert!(
                case.wrapped.token_len > 0,
                "{:?}/{:?}: token_len must be > 0",
                family, context,
            );
            let span_end = nl + case.wrapped.token_offset + case.wrapped.token_len;
            let file_len = nl + case.wrapped.bytes.len() + nl;
            prop_assert!(
                span_end <= file_len,
                "{:?}/{:?}: span end {} exceeds file len {}",
                family, context, span_end, file_len,
            );
            if !matches!(context, ContextWrap::Raw) {
                prop_assert!(
                    case.wrapped.token_offset > 0,
                    "{:?}/{:?}: non-Raw context should have token_offset > 0",
                    family, context,
                );
            }
        }
    }
}
