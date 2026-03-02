//! YAML rule deserialization and conversion to [`RuleSpec`].
//!
//! # Schema overview
//!
//! A YAML rules file is a mapping with a single `rules` key whose value is a
//! sequence of rule objects. Each rule must specify `name`, `regex`, `anchors`,
//! and `radius`; all other fields are optional. See [`YamlRule`] for the full
//! field set.
//!
//! Unknown fields are silently ignored (serde's default behavior) so that newer
//! YAML files can be read by older parser versions. The companion test
//! `default_rules_yaml_has_no_unknown_fields` catches accidental typos in the
//! canonical `default_rules.yaml`.
//!
//! # Conversion pipeline
//!
//! [`parse_yaml_rules`] transforms a YAML string into a `Vec<RuleSpec>` via
//! a three-stage pipeline applied per rule:
//!
//! 1. **Deserialize** — serde maps the YAML text into [`YamlRule`] structs,
//!    which mirror the on-disk schema using owned `String` / `Vec` types.
//! 2. **Compile regex** — the pattern string is compiled into a
//!    `regex::bytes::Regex` via [`super::build_regex`], which retries with
//!    progressively larger compile-size limits (both compiled regex and DFA
//!    cache) on `CompiledTooBig` errors. This
//!    step runs *outside* the interning lock to avoid holding the mutex
//!    during potentially expensive compilation.
//! 3. **Intern and assemble** — string/byte fields are interned into the
//!    global [`RuleAtomPool`] (producing `&'static` references), numeric and
//!    struct fields are converted directly, and a [`RuleSpec`] is emitted.
//!
//! During stage 3 the parser also applies *implicit defaults*: rules with
//! an entropy threshold at or above [`AUTO_CHAR_CLASS_ENTROPY_THRESHOLD`]
//! that lack an explicit `char_class` gate automatically receive one. This
//! eliminates per-rule boilerplate for the common case of high-entropy
//! secret patterns (API keys, tokens) while preserving opt-out capability.
//!
//! # Interning
//!
//! Parsed rule data — names, anchors, keywords, etc. — are interned into a
//! process-global [`RuleAtomPool`] and returned as `&'static` references.
//! This is intentional: rule literals live for the entire process, and
//! interning avoids repeated heap growth when the same YAML is parsed
//! multiple times (e.g. across configuration reloads).
//!
//! The pool is protected by a [`Mutex`] with poison recovery, so a panic
//! during interning does not permanently lock out subsequent callers.
//!
//! # Thread safety
//!
//! [`parse_yaml_rules`] is safe to call from multiple threads. The global
//! atom pool serializes interning but the critical section is short (hash
//! lookups and pointer copies for already-interned atoms).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use serde::Deserialize;

use crate::api::{
    CharClassSpec, EntropySpec, LocalContextSpec, OfflineValidationSpec, RuleSpec, TwoPhaseSpec,
    ValidatorKind,
};

use super::RulesError;

// ---------------------------------------------------------------------------
// Auto-enable char_class defaults
// ---------------------------------------------------------------------------

/// Minimum Shannon entropy threshold (bits/byte) for auto-enabling the
/// character-class distribution gate on rules that omit an explicit
/// `char_class` setting.
///
/// Rules at or above this threshold target high-entropy secrets (API keys,
/// tokens) where a predominantly-lowercase scan window is a reliable signal
/// for prose rather than a real secret. Rules below it target passwords or
/// low-entropy strings where the same gate would cause false negatives.
///
/// 3.0 bits/byte was chosen empirically: it separates low-entropy rules
/// (e.g. `nuget-config-password` at 1.0, `asana-client-id` at 2.5)
/// from token-oriented rules.
pub(crate) const AUTO_CHAR_CLASS_ENTROPY_THRESHOLD: f32 = 3.0;

/// Default max-lowercase-percentage for auto-enabled `char_class` gates.
///
/// A window with more than 95% lowercase ASCII bytes is almost certainly
/// natural-language prose rather than a secret. The 5% headroom accounts
/// for mixed-case identifiers or punctuation at window boundaries.
pub(crate) const AUTO_CHAR_CLASS_MAX_LOWER_PCT: u8 = 95;

/// Default minimum window length for auto-enabled `char_class` gates.
///
/// Windows shorter than 32 bytes do not contain enough samples for the
/// lowercase-percentage heuristic to be meaningful; applying it there
/// would introduce noise without filtering useful signal.
pub(crate) const AUTO_CHAR_CLASS_MIN_WINDOW_LEN: u16 = 32;

// ---------------------------------------------------------------------------
// YAML serde types
// ---------------------------------------------------------------------------

/// Top-level YAML structure: `{ rules: [...] }`.
///
/// This is the serde target for the entire rules file. The `rules` key
/// maps to a list of [`YamlRule`] objects.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlRulesFile {
    pub rules: Vec<YamlRule>,
}

/// One detection rule as expressed in YAML.
///
/// # Required fields
///
/// - `name` — unique rule identifier (e.g. `"generic-api-key"`).
/// - `regex` — pattern compiled into a [`regex::bytes::Regex`].
/// - `anchors` — literal byte strings used by the Vectorscan pre-filter
///   to narrow scan windows before the regex is applied.
/// - `radius` — byte radius around an anchor match to feed to the regex.
///
/// # Optional fields
///
/// All other fields default to `None` / absent. See the corresponding
/// `*Spec` types in [`crate::api`] for semantics.
///
/// `ValidatorKind` is intentionally absent from the YAML schema — fast
/// validators are tightly coupled to specific regex patterns and are only
/// set programmatically.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlRule {
    /// Unique rule identifier used for diagnostics and finding attribution.
    pub name: String,
    /// Pattern compiled into a [`regex::bytes::Regex`] during parsing.
    pub regex: String,
    /// Literal byte strings fed to the Vectorscan pre-filter; at least one
    /// must appear in the input for a scan window to be opened.
    pub anchors: Vec<String>,
    /// Byte radius around each anchor hit that defines the scan window.
    pub radius: usize,
    /// Cheap byte-substring gate applied before the regex. When set, the
    /// window must contain this literal or it is skipped entirely.
    #[serde(default)]
    pub must_contain: Option<String>,
    /// Local keyword gate (any-of). At least one keyword must appear in the
    /// scan window for the regex to run. Evaluated on raw window bytes,
    /// including auto-generated UTF-16LE/BE variants.
    #[serde(default)]
    pub keywords_any: Option<Vec<String>>,
    /// Post-match suppressor gate (any-of). If any literal appears inside
    /// the extracted secret bytes, the finding is silently dropped. Useful
    /// for filtering known placeholders like `EXAMPLE` or `DUMMY_TOKEN`.
    #[serde(default)]
    pub value_suppressors_any: Option<Vec<String>>,
    /// Shannon/min-entropy gate on the extracted secret. See [`YamlEntropy`].
    #[serde(default)]
    pub entropy: Option<YamlEntropy>,
    /// Character-class distribution pre-filter. See [`YamlCharClass`].
    /// When absent and entropy threshold >= 3.0 bits/byte, the parser
    /// auto-enables a default gate.
    #[serde(default)]
    pub char_class: Option<YamlCharClass>,
    /// Two-phase confirm-then-expand configuration. See [`YamlTwoPhase`].
    #[serde(default)]
    pub two_phase: Option<YamlTwoPhase>,
    /// Post-extraction structural context check. See [`YamlLocalContext`].
    #[serde(default)]
    pub local_context: Option<YamlLocalContext>,
    /// Offline structural validation (checksums, format checks).
    /// See [`YamlOfflineValidation`].
    #[serde(default)]
    pub offline_validation: Option<YamlOfflineValidation>,
    /// Capture group index for secret extraction. `None` uses the default
    /// heuristic (first non-empty capture in groups 1..N, else full match).
    #[serde(default)]
    pub secret_group: Option<u16>,
    /// When `true`, bypass the UUID-format quick-reject in the safelist.
    /// Required for providers that issue API keys in 8-4-4-4-12 hex format.
    #[serde(default)]
    pub uuid_format_secret: bool,
    /// Per-rule minimum confidence floor. Findings scoring below this are
    /// suppressed. `None` selects an auto-default derived from the rule's
    /// compiled gate configuration. Valid range: `0..=10`.
    #[serde(default)]
    pub min_confidence: Option<i8>,
}

/// Entropy gate parameters for a rule.
///
/// When present, the secret value (the captured group after regex matching)
/// must have at least `min_bits_per_byte` bits of Shannon entropy per byte.
/// Secrets shorter than `min_len` bypass the entropy check entirely because
/// Shannon entropy is noisy on small samples; secrets longer than `max_len`
/// are evaluated on only the first `max_len` bytes to bound compute cost.
///
/// An optional `min_entropy_bits_per_byte` adds a second, stricter gate
/// based on min-entropy (NIST SP 800-90B). Min-entropy measures the
/// probability of the single most frequent byte, catching skewed
/// distributions where one byte value dominates even though the Shannon
/// entropy across all byte values looks moderate.
///
/// `digit_penalty` is an opt-in false-positive reducer for hex-like rules:
/// when enabled, all-digit candidates in the evaluated entropy slice (after
/// `max_len` capping) are penalized by `DIGIT_ONLY_PENALTY_NUMERATOR /
/// log2(len)` before Shannon threshold comparison (`len == 1` is left
/// unpenalized). See [`engine::helpers::entropy::DIGIT_ONLY_PENALTY_NUMERATOR`].
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlEntropy {
    /// Shannon entropy threshold in bits/byte. Secrets below this are
    /// rejected as likely false positives. Valid range: `[0.0, 8.0]`.
    pub min_bits_per_byte: f32,
    /// Secrets shorter than this length bypass the entropy check entirely
    /// because Shannon entropy is unreliable on small samples.
    pub min_len: usize,
    /// Maximum bytes evaluated for entropy. Longer secrets are capped to
    /// bound compute cost without rejecting the entire candidate.
    pub max_len: usize,
    /// Optional stricter gate based on NIST SP 800-90B min-entropy.
    /// Catches byte distributions skewed toward a single dominant value
    /// that Shannon entropy alone may miss. `None` disables this gate.
    #[serde(default)]
    pub min_entropy_bits_per_byte: Option<f32>,
    /// When `true`, all-digit candidates in the evaluated entropy slice
    /// are penalized by `DIGIT_ONLY_PENALTY_NUMERATOR / log2(len)` before
    /// the Shannon threshold comparison. Targets false positives from
    /// numeric-only strings in hex-like rules (e.g. version numbers,
    /// timestamps).
    #[serde(default)]
    pub digit_penalty: bool,
}

/// Character-class pre-filter gate parameters for a rule.
///
/// When present, scan windows whose byte composition exceeds `max_lower_pct`
/// percent lowercase ASCII (`a`–`z`) **and** are at least `min_window_len`
/// bytes long are rejected before the regex is applied.
///
/// If this section is absent (or explicitly `null`) in YAML **and** the rule
/// has an entropy threshold at or above [`AUTO_CHAR_CLASS_ENTROPY_THRESHOLD`],
/// the parser auto-enables a gate with the `AUTO_CHAR_CLASS_*` defaults.
/// To opt out of auto-enable, set `char_class` to a no-op configuration
/// such as `{ max_lower_pct: 100, min_window_len: 16 }`.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlCharClass {
    /// Maximum percentage of lowercase ASCII bytes (`a`-`z`) allowed in
    /// the scan window. Windows exceeding this are rejected. Range: 0-100.
    pub max_lower_pct: u8,
    /// Minimum window length (bytes) for the gate to apply. Shorter
    /// windows pass unconditionally because the percentage is too noisy.
    pub min_window_len: u16,
}

/// Two-phase scanning configuration.
///
/// Two-phase scanning trades a small literal-search pass for a large
/// reduction in regex work on rules whose `full_radius` is wide but
/// whose actual matches cluster around confirming literals.
///
/// - **Phase 1** — extract a narrow window (`seed_radius` bytes around
///   the anchor hit) and scan it for at least one `confirm_any` literal.
///   Windows without a confirming literal are dropped immediately.
/// - **Phase 2** — expand surviving windows from `seed_radius` to
///   `full_radius` and run the regex on the wider view.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlTwoPhase {
    /// Narrow window radius (bytes) for the cheap Phase 1 literal scan.
    pub seed_radius: usize,
    /// Expanded window radius (bytes) for Phase 2 regex evaluation.
    /// Must be >= `seed_radius`.
    pub full_radius: usize,
    /// Confirming literals (any-of). At least one must appear in the
    /// seed window or the candidate is dropped before Phase 2.
    pub confirm_any: Vec<String>,
}

/// Local-context validation for reducing false positives.
///
/// Examines the bytes immediately surrounding a regex match
/// (`lookbehind` bytes before, `lookahead` bytes after) for structural
/// cues such as assignment operators, quoting, or specific key names.
/// If none of the enabled checks pass, the finding is suppressed — the
/// assumption being that a regex-matched value without surrounding
/// assignment/quoting context is unlikely to be an actual secret in use.
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlLocalContext {
    /// Bytes to examine before the start of the secret span.
    pub lookbehind: usize,
    /// Bytes to examine after the end of the secret span.
    pub lookahead: usize,
    /// Require an assignment separator (`=`, `:`, or `>`) on the same line
    /// preceding the secret. Catches unanchored regex matches in prose.
    #[serde(default)]
    pub require_same_line_assignment: bool,
    /// Require the secret to be wrapped in matching quotes (`"`, `'`, or `` ` ``).
    #[serde(default)]
    pub require_quoted: bool,
    /// Key names (any-of) that must appear on the same line as the match.
    /// When `None`, no key-name check is performed.
    #[serde(default)]
    pub key_names_any: Option<Vec<String>>,
}

/// Offline structural validation configuration.
///
/// The YAML `type` key (renamed to `kind` in Rust to avoid the keyword
/// collision) selects the validation algorithm. Parameterised variants
/// (currently only `crc32_base62`) require additional numeric fields; unit
/// variants need only the type selector.
///
/// Conversion to [`OfflineValidationSpec`] is performed by
/// [`yaml_offline_to_spec`], which rejects unknown type strings.
///
/// # Supported types
///
/// | YAML `type` value          | Maps to                                |
/// |----------------------------|----------------------------------------|
/// | `crc32_base62`             | [`OfflineValidationSpec::Crc32Base62`] |
/// | `github_fine_grained_pat`  | [`OfflineValidationSpec::GithubFinegrainedPat`] |
/// | `grafana_service_account`  | [`OfflineValidationSpec::GrafanaServiceAccount`] |
/// | `aws_access_key`           | [`OfflineValidationSpec::AwsAccessKey`] |
/// | `sentry_org_token`         | [`OfflineValidationSpec::SentryOrgToken`] |
/// | `pypi_token`               | [`OfflineValidationSpec::PyPiToken`]            |
/// | `slack_token`              | [`OfflineValidationSpec::SlackToken`]           |
#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
pub(crate) struct YamlOfflineValidation {
    /// Validation algorithm selector. Renamed from `type` in YAML to
    /// avoid the Rust keyword. See the struct-level table for valid values.
    #[serde(rename = "type")]
    pub kind: String,
    /// Bytes to skip before the payload region. Required for `crc32_base62`.
    #[serde(default)]
    pub prefix_skip: Option<u8>,
    /// Length of the payload region in bytes. Required for `crc32_base62`.
    #[serde(default)]
    pub payload_len: Option<u8>,
    /// Length of the base-62-encoded CRC-32 checksum. Required for
    /// `crc32_base62`; must be <= 6 (max digits for a `u32` in base 62).
    #[serde(default)]
    pub checksum_len: Option<u8>,
}

// ---------------------------------------------------------------------------
// Atom interning — rules live for the entire process, so we store interned
// allocations in a global pool and reuse them across parse calls.
// ---------------------------------------------------------------------------

/// Content-addressed interning pool for rule atoms.
///
/// Each `intern_*` method returns a `&'static` reference. If the value
/// was already interned, the existing pointer is returned (dedup by
/// content equality). Otherwise, the value is `Box::leak`-ed into
/// process-lifetime storage and inserted into the lookup table.
///
/// Three maps cover the three shapes needed by [`RuleSpec`]:
/// - `strings` — rule names (`&'static str`).
/// - `bytes` — individual byte slices (anchors, keywords, etc.).
/// - `bytes_slices` — slices-of-slices (e.g. the full anchors array).
///
/// # Memory characteristics
///
/// `Box::leak` makes each interned value permanently live. The
/// `HashMap` keys duplicate the content for lookup, so total memory is
/// roughly 2x the unique atom set. This is acceptable because the rule
/// corpus is small (hundreds of rules, each with a few short literals)
/// and parse calls with identical YAML hit the dedup path with zero
/// additional allocation.
///
/// Growth is bounded by the number of *distinct* atom values across all
/// `parse_yaml_rules` calls for the lifetime of the process.
#[derive(Default)]
struct RuleAtomPool {
    /// Rule names: owned `String` key -> leaked `&'static str`.
    strings: HashMap<String, &'static str>,
    /// Individual byte atoms (anchors, keywords, must_contain literals):
    /// owned `Vec<u8>` key -> leaked `&'static [u8]`.
    bytes: HashMap<Vec<u8>, &'static [u8]>,
    /// Composite byte-slice arrays (anchor lists, keyword lists):
    /// owned `Vec<Vec<u8>>` key -> leaked `&'static [&'static [u8]]`.
    /// Inner slices are also interned via `bytes` for cross-rule sharing.
    bytes_slices: HashMap<Vec<Vec<u8>>, &'static [&'static [u8]]>,
}

impl RuleAtomPool {
    /// Intern a string, returning a `&'static str` that is pointer-equal
    /// across calls with the same content.
    ///
    /// On the first call for a given string, the owned `String` is cloned
    /// into a `Box<str>` and leaked. The clone is necessary because the
    /// original `String` is consumed as the `HashMap` key for future lookups.
    fn intern_str(&mut self, s: String) -> &'static str {
        if let Some(existing) = self.strings.get(&s) {
            return existing;
        }
        let leaked = Box::leak(s.clone().into_boxed_str());
        self.strings.insert(s, leaked);
        leaked
    }

    /// Intern a string's UTF-8 bytes, delegating to [`Self::intern_bytes_vec`].
    ///
    /// This is a convenience entry point for fields that arrive as `String`
    /// from serde but are stored as `&'static [u8]` in [`RuleSpec`] (e.g.
    /// `must_contain`, individual anchors).
    fn intern_bytes(&mut self, s: String) -> &'static [u8] {
        self.intern_bytes_vec(s.into_bytes())
    }

    /// Intern a raw byte vector, deduplicating by content.
    fn intern_bytes_vec(&mut self, bytes: Vec<u8>) -> &'static [u8] {
        if let Some(existing) = self.bytes.get(&bytes) {
            return existing;
        }
        let leaked = Box::leak(bytes.clone().into_boxed_slice());
        self.bytes.insert(bytes, leaked);
        leaked
    }

    /// Intern a list of strings as a `&'static [&'static [u8]]`.
    ///
    /// Both the outer slice and each inner byte slice are interned
    /// independently via [`Self::intern_bytes_vec`], so element-level
    /// sharing works across rules that happen to share individual
    /// keywords or anchors.
    fn intern_bytes_slice(&mut self, values: Vec<String>) -> &'static [&'static [u8]] {
        let keys: Vec<Vec<u8>> = values.into_iter().map(String::into_bytes).collect();
        if let Some(existing) = self.bytes_slices.get(&keys) {
            return existing;
        }

        let mut refs: Vec<&'static [u8]> = Vec::with_capacity(keys.len());
        for key in &keys {
            refs.push(self.intern_bytes_vec(key.clone()));
        }
        let leaked = Box::leak(refs.into_boxed_slice());
        self.bytes_slices.insert(keys, leaked);
        leaked
    }
}

/// Process-global interning pool for rule atom data.
///
/// `LazyLock` defers allocation until the first `parse_yaml_rules` call.
/// The `Mutex` serializes concurrent access; the critical section is
/// dominated by `HashMap` lookups (O(1) amortized) so contention is
/// negligible in practice.
static RULE_ATOMS: LazyLock<Mutex<RuleAtomPool>> =
    LazyLock::new(|| Mutex::new(RuleAtomPool::default()));

/// Acquire the global atom pool and run `f` under the lock.
///
/// Poison recovery (`into_inner`) is deliberate: a prior panic during
/// interning leaves the pool in a consistent state (partial inserts are
/// harmless because `Box::leak` is idempotent for the leaked value) so
/// subsequent callers should not be blocked.
fn with_rule_atoms<T>(f: impl FnOnce(&mut RuleAtomPool) -> T) -> T {
    let mut guard = RULE_ATOMS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut guard)
}

// ---------------------------------------------------------------------------
// Core conversion
// ---------------------------------------------------------------------------

/// Convert a [`YamlOfflineValidation`] into an [`OfflineValidationSpec`].
///
/// The `crc32_base62` type requires all three numeric parameters (`prefix_skip`,
/// `payload_len`, `checksum_len`); all other types are unit variants that need
/// only the `type` selector. Returns an error for unknown type strings or
/// missing required parameters.
fn yaml_offline_to_spec(
    rule_name: &str,
    ov: YamlOfflineValidation,
) -> Result<OfflineValidationSpec, RulesError> {
    match ov.kind.as_str() {
        "crc32_base62" => {
            let prefix_skip = ov
                .prefix_skip
                .ok_or_else(|| RulesError::OfflineValidation {
                    rule_name: rule_name.to_string(),
                    message: "crc32_base62 requires 'prefix_skip'".into(),
                })?;
            let payload_len = ov
                .payload_len
                .ok_or_else(|| RulesError::OfflineValidation {
                    rule_name: rule_name.to_string(),
                    message: "crc32_base62 requires 'payload_len'".into(),
                })?;
            let checksum_len = ov
                .checksum_len
                .ok_or_else(|| RulesError::OfflineValidation {
                    rule_name: rule_name.to_string(),
                    message: "crc32_base62 requires 'checksum_len'".into(),
                })?;
            Ok(OfflineValidationSpec::Crc32Base62 {
                prefix_skip,
                payload_len,
                checksum_len,
            })
        }
        "github_fine_grained_pat" => Ok(OfflineValidationSpec::GithubFinegrainedPat),
        "grafana_service_account" => Ok(OfflineValidationSpec::GrafanaServiceAccount),
        "aws_access_key" => Ok(OfflineValidationSpec::AwsAccessKey),
        "sentry_org_token" => Ok(OfflineValidationSpec::SentryOrgToken),
        "pypi_token" => Ok(OfflineValidationSpec::PyPiToken),
        "slack_token" => Ok(OfflineValidationSpec::SlackToken),
        unknown => Err(RulesError::OfflineValidation {
            rule_name: rule_name.to_string(),
            message: format!("unknown offline_validation type '{unknown}'"),
        }),
    }
}

/// Parse YAML content into a `Vec<RuleSpec>`.
///
/// Deserializes the YAML, then converts each [`YamlRule`] into a [`RuleSpec`]
/// by compiling regexes and interning textual fields into reusable `'static`
/// references via the global [`RuleAtomPool`].
///
/// # Processing order per rule
///
/// 1. Compile the regex pattern (outside the interning lock).
/// 2. Intern string/byte fields under the global atom pool lock.
/// 3. Map gate config fields (`entropy`, `char_class`) directly.
/// 4. Apply implicit defaults — auto-enable `char_class` when entropy
///    threshold >= [`AUTO_CHAR_CLASS_ENTROPY_THRESHOLD`] and no explicit
///    gate is provided.
/// 5. Convert `offline_validation` via [`yaml_offline_to_spec`].
/// 6. Assemble the final [`RuleSpec`].
///
/// Note that this function performs *no* semantic validation beyond regex
/// compilation and offline-validation type mapping. Higher-level checks
/// (e.g. `assert_valid()`) are the caller's responsibility — see
/// [`super::load_rules_from_content`].
///
/// # Errors
///
/// - [`RulesError::Yaml`] — the input is not valid YAML or does not match
///   the expected schema (missing required fields).
/// - [`RulesError::Regex`] — a rule's `regex` field fails to compile.
///   The error includes the rule name and pattern for diagnostics.
/// - [`RulesError::OfflineValidation`] — an `offline_validation` block
///   specifies an unknown type or is missing required parameters.
pub(crate) fn parse_yaml_rules(content: &str) -> Result<Vec<RuleSpec>, RulesError> {
    let file: YamlRulesFile = serde_norway::from_str(content).map_err(RulesError::Yaml)?;

    let mut rules = Vec::with_capacity(file.rules.len());
    for yr in file.rules {
        let YamlRule {
            name,
            regex,
            anchors,
            radius,
            must_contain,
            keywords_any,
            value_suppressors_any,
            entropy,
            char_class,
            two_phase,
            local_context,
            offline_validation,
            secret_group,
            uuid_format_secret,
            min_confidence,
        } = yr;

        let re = super::build_regex(&regex).map_err(|error| RulesError::Regex {
            rule_name: name.clone(),
            pattern: regex.clone(),
            error,
        })?;

        let (
            name,
            anchors,
            must_contain,
            keywords_any,
            value_suppressors_any,
            two_phase,
            local_context,
        ) = with_rule_atoms(|atoms| {
            let anchors = atoms.intern_bytes_slice(anchors);
            let must_contain = must_contain.map(|s| atoms.intern_bytes(s));
            let keywords_any = keywords_any.map(|kws| atoms.intern_bytes_slice(kws));
            let value_suppressors_any =
                value_suppressors_any.map(|vs| atoms.intern_bytes_slice(vs));
            let two_phase = two_phase.map(|tp| TwoPhaseSpec {
                seed_radius: tp.seed_radius,
                full_radius: tp.full_radius,
                confirm_any: atoms.intern_bytes_slice(tp.confirm_any),
            });
            let local_context = local_context.map(|lc| LocalContextSpec {
                lookbehind: lc.lookbehind,
                lookahead: lc.lookahead,
                require_same_line_assignment: lc.require_same_line_assignment,
                require_quoted: lc.require_quoted,
                key_names_any: lc.key_names_any.map(|keys| atoms.intern_bytes_slice(keys)),
            });
            (
                atoms.intern_str(name),
                anchors,
                must_contain,
                keywords_any,
                value_suppressors_any,
                two_phase,
                local_context,
            )
        });

        let entropy = entropy.map(|e| EntropySpec {
            min_bits_per_byte: e.min_bits_per_byte,
            min_len: e.min_len,
            max_len: e.max_len,
            min_entropy_bits_per_byte: e.min_entropy_bits_per_byte,
            digit_penalty: e.digit_penalty,
        });

        let char_class = char_class.map(|cc| CharClassSpec {
            max_lower_pct: cc.max_lower_pct,
            min_window_len: cc.min_window_len,
        });

        // Auto-enable char_class for high-entropy rules that don't explicitly
        // set it. Rules with entropy threshold >= 3.0 bits/byte are scanning
        // for secrets (API keys, tokens), not passwords or low-entropy strings.
        // Excludes low-entropy password-like rules (e.g. nuget-config-password
        // at 1.0).
        //
        // Note: `char_class: null` in YAML deserializes to `None` (same as
        // absent), so auto-enable fires for both. This is standard serde/YAML
        // behavior. To opt out, set `char_class: { max_lower_pct: 100, min_window_len: 16 }`
        // which effectively disables the gate.
        let char_class = char_class.or_else(|| {
            entropy.as_ref().and_then(|ent| {
                if ent.min_bits_per_byte >= AUTO_CHAR_CLASS_ENTROPY_THRESHOLD {
                    Some(CharClassSpec {
                        max_lower_pct: AUTO_CHAR_CLASS_MAX_LOWER_PCT,
                        min_window_len: AUTO_CHAR_CLASS_MIN_WINDOW_LEN,
                    })
                } else {
                    None
                }
            })
        });

        let offline_validation = offline_validation
            .map(|ov| yaml_offline_to_spec(name, ov))
            .transpose()?;

        rules.push(RuleSpec {
            name,
            anchors,
            radius,
            // NOTE: ValidatorKind is not expressible in the YAML schema.
            // Fast validators are tightly coupled to specific regex patterns
            // and are only set programmatically. All YAML-loaded rules use None.
            validator: ValidatorKind::None,
            two_phase,
            must_contain,
            keywords_any,
            value_suppressors_any,
            entropy,
            char_class,
            local_context,
            offline_validation,
            uuid_format_secret,
            secret_group,
            min_confidence,
            re,
        });
    }

    Ok(rules)
}

#[cfg(test)]
#[path = "yaml_unit_tests.rs"]
mod tests;

/// Property-based parser/interning invariants live in a sibling module to
/// keep this file's unit tests focused and to preserve fast default
/// `cargo test` (proptest runs only with `--features stdx-proptest`).
#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "yaml_tests.rs"]
mod yaml_tests;
