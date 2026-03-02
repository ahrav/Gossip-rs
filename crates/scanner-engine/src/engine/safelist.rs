//! Global context safelist for emit-time suppression.
//!
//! The safelist is intentionally broad and conservative: if any pattern matches
//! nearby context for a finding, the finding is suppressed before it is
//! recorded.
//!
//! # Scope and Matching Model
//! - Matching runs on caller-provided context windows around already-detected
//!   candidates; this module does not search entire files on its own.
//! - Matching uses `RegexSet` ANY semantics: one pattern hit is enough to
//!   classify the context as safelisted.
//! - Patterns are tuned for synthetic/demo/placeholder recall. False positives
//!   are acceptable because this filter is only a suppression hint after
//!   detection, not a standalone detector.
//!
//! # Three-Component Matching
//!
//! The safelist uses three matching components:
//!
//! 1. **Context-window tier** (`regex_set`, 18 patterns): matches the full
//!    context buffer around a finding. Patterns may use context anchors like
//!    `[:=]\s*` or `(?m)^` that only make sense in surrounding text.
//!
//! 2. **Secret-bytes tier** (`secret_bytes_set`, 9 patterns): matches the
//!    extracted secret value directly (10–150 bytes typically). Only patterns
//!    that are meaningful on bare values are included — context-anchored
//!    patterns and short substrings ("mock") that risk false suppression of
//!    real secrets are excluded. Patterns for known placeholder values use
//!    `^...$` anchoring to prevent false suppression of composite secrets
//!    containing placeholder words as hyphen/dot-separated segments (e.g.,
//!    `key-null-safety-9xK2mB`). Structural markers (redaction runs,
//!    template variables, base64 literals) remain as substring matches.
//!
//! 3. **UUID-format quick-reject** ([`is_uuid_format`]): a procedural byte
//!    check that recognizes the canonical 8-4-4-4-12 hyphenated hex UUID
//!    format. Gated per-rule by `RuleCompiled::uuid_format_secret()` so that
//!    rules intentionally capturing UUID-format secrets (e.g., Heroku, Snyk
//!    API keys) bypass suppression. Structural-only — no version/variant
//!    validation per RFC 9562.
//!
//! All three components are checked during `apply_emit_time_policy`. The
//! context tier runs first (root findings only); then the secret-bytes tier
//! and UUID quick-reject run on all findings (including decoded/
//! transform-derived) when the context tier does not suppress.
//!
//! # Invariants
//! - Pattern inventory is fixed at 18 context categories and 9 secret-bytes
//!   categories; changes require updating the corresponding `*_COUNT` constant
//!   and the compile-time assertions.
//! - Matching is byte-oriented and uses `regex::bytes::RegexSet` (ANY semantics).
//! - Case-insensitive handling is encoded inline in patterns via `(?i)` where needed.
//!
//! # Edge Cases
//! - Context may be non-UTF-8; byte regexes keep matching behavior stable.
//! - Extremely narrow caller-provided context windows can miss safelist markers,
//!   which is a deliberate trade-off controlled by the caller.
//!
//! # Complexity
//! - Construction cost is paid once per filter instance.
//! - `matcher().is_match(...)` is effectively linear in context length for a
//!   fixed pattern set.
//!
//! # Failure Modes
//! - A compile-time assertion guards both pattern counts; adding or removing
//!   patterns without updating the count constants is a compile error.
//! - Construction panics if any pattern is invalid; this is treated as a build-time
//!   configuration bug, not a recoverable runtime condition.

use regex::bytes::RegexSet;

/// Number of patterns in the context-window safelist.
///
/// Tied to [`SAFELIST_PATTERNS`] by the `const _` assertion below. Any addition
/// or removal of a pattern requires updating this constant.
const SAFELIST_PATTERN_COUNT: usize = 18;

/// Context-window safelist patterns for emit-time suppression.
///
/// Each entry targets a category of synthetic, demo, or placeholder context
/// that signals a detected secret is not real. Categories span six themes:
///
/// - **Placeholder markers** (idx 0, 6, 7, 13): known fake values, sentinel
///   words, sequential demo strings, and insert-your-X markers.
/// - **Infrastructure references** (idx 3, 4, 9, 10): shell variables,
///   random-generator commands, template variables, and localhost URIs.
/// - **Metadata/schema noise** (idx 5, 8, 11, 12, 17): assignment-prefixed
///   metadata values, XML namespace declarations, secret-manager markup,
///   documentation prose, and hash output lines.
/// - **Redaction and placeholder encodings** (idx 2, 14): asterisk redaction
///   runs and base64 encodings of the words "example", "test", and "sample".
/// - **Source control artifacts** (idx 1, 15): AWS example key IDs and git
///   conflict markers.
/// - **Test infrastructure** (idx 16): test fixture and mock path markers.
///
/// Patterns use `(?i)` for case-insensitivity where needed and
/// `regex::bytes::RegexSet` ANY semantics (one hit suppresses). The full
/// pattern set is only applied to context windows around root findings; for
/// bare secret values, see [`SECRET_BYTES_PATTERNS`].
const SAFELIST_PATTERNS: &[&str] = &[
    // Placeholder markers plus key/token/secret nouns.
    r"(?i)\b(?:placeholder|dummy|fake|sample|example|test)[-_ ]{0,3}(?:key|token|secret|password)\b|\b(?:key|token|secret|password)[-_ ]{0,3}(?:placeholder|dummy|fake|sample|example|test)\b",
    // AWS example key IDs (AKIA...EXAMPLE).
    r"\bAKIA[0-9A-Z]{9}EXAMPLE\b",
    // Redaction marker runs (***).
    r"\*{3,}",
    // Shell variable references in assigned values ($VAR, ${VAR}).
    r"[:=]\s*(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)",
    // Random generator shell commands ($(openssl...), $(uuidgen...)).
    r"(?i)\$\((?:openssl|uuidgen)\b[^)]*\)",
    // Metadata marker values (null, changeme, todo, fixme).
    r"(?i)[:=]\s*(?:null|changeme|todo|fixme)\b",
    // Known fake sample value hunter2.
    r"(?i)\bhunter2\b",
    // Sequential demo strings (0123456789, abcdefghij).
    r"(?i)\b(?:0123456789|abcdefghij)\b",
    // Schema/classpath/XML namespace references.
    r#"(?i)\b(?:classpath:[^\s"'`]+|xsi:schemaLocation\b|xmlns(?::[A-Za-z0-9_-]+)?=)"#,
    // Template vars (${FOO}, {{FOO}}).
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[A-Za-z_][A-Za-z0-9_]*\}\})",
    // Example/localhost URIs.
    r#"(?i)\b(?:https?|ssh)://(?:localhost|(?:[A-Za-z0-9-]+\.)*example(?:\.[A-Za-z]{2,})?)(?::\d+)?(?:/[^\s"']*)?"#,
    // Secret-manager markup/tags.
    r"(?i)(?:<\s*/?\s*(?:secret|token|password)\s*>|(?:secretmanager|vault)://|secret(?:manager)?[:=])",
    // Documentation prose markers (for example, sample config).
    r"(?i)\b(?:for example|sample config|example config)\b",
    // INSERT_YOUR / REPLACE_WITH style markers.
    r"(?i)\b(?:INSERT[_\s-]?YOUR|REPLACE[_\s-]?WITH)[A-Z0-9_\s-]*\b",
    // Base64 for example/test/sample literals.
    r"(?:ZXhhbXBsZQ==|c2FtcGxl={0,2}|dGVzdA==)",
    // Git conflict markers.
    r"(?m)^(?:<{7}|={7}|>{7})(?: .*)?$",
    // Test fixture path markers (__test__, fixture, mock).
    r"(?i)\b(?:__tests?__|fixtures?|mocks?)\b",
    // Hash output format lines (sha256: ..., md5=...).
    r"(?i)\b(?:sha(?:1|224|256|384|512)|md5)\s*[:=]\s*[A-Fa-f0-9]{8,}\b",
];

const _: () = assert!(SAFELIST_PATTERNS.len() == SAFELIST_PATTERN_COUNT);

/// Number of patterns in the secret-bytes safelist subset.
///
/// This curated subset contains only patterns that are meaningful when matched
/// against bare extracted secret values (10–150 bytes). Context-anchored
/// patterns (e.g., `[:=]\s*`, `(?m)^`) and short substrings that risk
/// suppressing real secrets (e.g., "mock") are excluded.
///
/// # Pattern provenance (indices refer to `SAFELIST_PATTERNS`):
///
/// | Idx | Category | Included | Reason |
/// |-----|----------|----------|--------|
/// | 0   | placeholder+noun | YES | Self-contained word pairs |
/// | 1   | AWS example key  | YES | Self-contained literal |
/// | 2   | Redaction runs   | YES | Pure value match |
/// | 5   | Metadata values  | YES | Modified: `[:=]\s*` prefix removed |
/// | 6   | hunter2          | YES | Pure value match |
/// | 7   | Sequential digits/alpha | YES | Pure value match |
/// | 9   | Template vars    | YES | Unresolved templates aren't real secrets |
/// | 13  | INSERT_YOUR/REPLACE_WITH | YES | Pure value match |
/// | 14  | Base64 example literals  | YES | Pure value match |
/// | 3,4,8,10,11,12,15,17 | Context-anchored | NO | Meaningless on bare values |
/// | 16  | Test fixture markers     | NO | "mock" is 4 chars, would suppress real keys |
const SECRET_BYTES_PATTERN_COUNT: usize = 9;

/// Patterns safe for matching against bare extracted secret bytes.
///
/// Each pattern is derived from `SAFELIST_PATTERNS` but adapted for bare-value
/// matching. Context anchors (`[:=]\s*`, `(?m)^`, URL structure) are stripped
/// because extracted secret bytes lack surrounding assignment or line context.
///
/// # Anchoring strategy
///
/// Patterns for known placeholder values (indices 0, 1, 3, 4, 5, 7) use
/// `^...$` anchoring instead of `\b` word boundaries. The `\b` assertion
/// treats hyphens, dots, and underscores as non-word characters, which means
/// composite secrets like `key-null-safety-9xK2mB` would falsely trigger the
/// `null` pattern at the segment boundary. Full-value anchoring ensures only
/// exact matches suppress. Structural markers (redaction runs `\*{3,}`,
/// template vars, base64 literals) remain as substring matches because their
/// delimiters are reliable.
///
/// # Safety against false suppression
///
/// Pattern 16 ("mock"/"fixture") is deliberately excluded: the short word
/// "mock" would match at word boundaries in keys containing separators
/// (e.g., `abc-mock-xyz`), and "fixture"/"__test__" are context-dependent
/// markers unsuitable for bare-value matching. See TruffleHog #2620 for a
/// real-world incident where over-broad value filtering suppressed valid
/// AWS credentials.
const SECRET_BYTES_PATTERNS: &[&str] = &[
    // [from idx 0] Placeholder markers plus key/token/secret nouns.
    // Anchored with ^...$ because the input is the extracted secret value.
    r"(?i)^(?:placeholder|dummy|fake|sample|example|test)[-_ ]{0,3}(?:key|token|secret|password)$|^(?:key|token|secret|password)[-_ ]{0,3}(?:placeholder|dummy|fake|sample|example|test)$",
    // [from idx 1] AWS example key IDs (AKIA...EXAMPLE).
    r"^AKIA[0-9A-Z]{9}EXAMPLE$",
    // [from idx 2] Redaction marker runs (***).
    r"\*{3,}",
    // [from idx 5] Metadata marker values — prefix-free variant for bare values.
    // Anchored: must be the entire extracted value, not a segment in a composite key.
    r"(?i)^(?:null|changeme|todo|fixme)$",
    // [from idx 6] Known fake sample value hunter2.
    r"(?i)^hunter2$",
    // [from idx 7] Sequential demo strings (0123456789, abcdefghij).
    r"(?i)^(?:0123456789|abcdefghij)$",
    // [from idx 9] Template vars (${FOO}, {{FOO}}).
    r"(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\{\{[A-Za-z_][A-Za-z0-9_]*\}\})",
    // [from idx 13] INSERT_YOUR / REPLACE_WITH style markers.
    // Anchored: must be the entire extracted value.
    r"(?i)^(?:INSERT[_\s-]?YOUR|REPLACE[_\s-]?WITH)[A-Z0-9_\s-]*$",
    // [from idx 14] Base64 for example/test/sample literals.
    r"(?:ZXhhbXBsZQ==|c2FtcGxl={0,2}|dGVzdA==)",
];

const _: () = assert!(SECRET_BYTES_PATTERNS.len() == SECRET_BYTES_PATTERN_COUNT);

/// Returns `true` if `bytes` is a canonical UUID: 8-4-4-4-12 hyphenated
/// hex, case-insensitive. Structural-only — no version/variant validation
/// per RFC 9562.
///
/// Hyphenated format only — 32-char hex without hyphens is deliberately
/// excluded because it collides with MD5/SHA/AES key representations.
/// Full-value check (not substring) prevents the TruffleHog #1953
/// false-negative pattern on composite secrets.
#[inline(always)]
pub(crate) fn is_uuid_format(bytes: &[u8]) -> bool {
    if bytes.len() != 36 {
        return false;
    }
    bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, &c)| matches!(i, 8 | 13 | 18 | 23) || c.is_ascii_hexdigit())
}

/// Precompiled global safelist matcher used for emit-time suppression.
///
/// Contains two matching components:
/// - `regex_set`: the full 18-pattern set for context-window matching.
/// - `secret_bytes_set`: a curated 9-pattern subset for bare secret-value matching.
///
/// UUID-format quick-reject is handled by the module-level [`is_uuid_format`]
/// function rather than a compiled regex. It is gated per-rule by
/// `RuleCompiled::uuid_format_secret()` so rules that intentionally capture
/// UUID-format secrets (e.g., Heroku, Snyk API keys) bypass suppression.
///
/// Constructed once during [`Engine`] initialization and stored as `self.safelist`.
/// Immutable after construction and `Send + Sync`, so it can be shared across
/// concurrent scan threads without additional synchronization.
///
/// [`Engine`]: super::Engine
#[derive(Debug)]
pub(crate) struct SafelistFilter {
    /// Full 18-pattern set for context-window matching (root findings only).
    regex_set: RegexSet,
    /// Curated 9-pattern subset for bare secret-value matching (all findings).
    secret_bytes_set: RegexSet,
}

impl SafelistFilter {
    /// Compile the static safelist pattern inventories into `RegexSet`s.
    ///
    /// Panics if any regex fails to compile. Pattern counts are enforced at
    /// compile time by the `const _` assertions above.
    pub(crate) fn new() -> Self {
        let regex_set = RegexSet::new(SAFELIST_PATTERNS).unwrap_or_else(|e| {
            panic!(
                "safelist pattern compilation failed ({} patterns): {e}",
                SAFELIST_PATTERNS.len()
            )
        });
        let secret_bytes_set = RegexSet::new(SECRET_BYTES_PATTERNS).unwrap_or_else(|e| {
            panic!(
                "secret-bytes safelist pattern compilation failed ({} patterns): {e}",
                SECRET_BYTES_PATTERNS.len()
            )
        });
        Self {
            regex_set,
            secret_bytes_set,
        }
    }

    /// Returns the context-window `RegexSet` (the full 18-pattern set).
    ///
    /// Callers pass a byte slice of the surrounding context window — not the
    /// bare secret value — and check `is_match(context_bytes)`. For matching
    /// against the extracted secret alone, use [`secret_bytes_matcher`] instead.
    ///
    /// [`secret_bytes_matcher`]: Self::secret_bytes_matcher
    #[inline]
    pub(crate) fn matcher(&self) -> &RegexSet {
        &self.regex_set
    }

    /// Returns a reference to the secret-bytes matcher.
    ///
    /// This uses a curated subset of patterns safe for matching against bare
    /// extracted secret values (typically 10–150 bytes). Unlike [`matcher`],
    /// which targets the surrounding context window of root findings only, this
    /// set is intended for **all** findings — including decoded and
    /// transform-derived values — because placeholder values are equally fake
    /// regardless of their surrounding context or encoding layer.
    ///
    /// Context-anchored patterns and short substrings that risk false
    /// suppression are excluded. See [`SECRET_BYTES_PATTERNS`] for the full
    /// inclusion/exclusion rationale.
    #[inline]
    pub(crate) fn secret_bytes_matcher(&self) -> &RegexSet {
        &self.secret_bytes_set
    }
}

#[cfg(test)]
mod tests {
    //! Test structure:
    //!
    //! - **Inventory counts**: verify `*_COUNT` constants match array lengths.
    //! - **Positive/negative coverage**: each context-window and secret-bytes
    //!   category has a positive example that must match and negative examples
    //!   (realistic secrets) that must not.
    //! - **Anchoring safety**: composite secrets containing placeholder words as
    //!   hyphenated segments must not be falsely suppressed (the `^...$`
    //!   anchoring regression tests).
    //! - **Provenance enforcement**: the included/excluded index lists are
    //!   checked for disjointness and full coverage of `SAFELIST_PATTERNS`.
    //! - **UUID quick-reject**: RFC 9562 examples, non-UUID rejection, and
    //!   anchoring tests that prevent substring matching inside composite
    //!   secrets.

    use super::{
        SAFELIST_PATTERN_COUNT, SAFELIST_PATTERNS, SECRET_BYTES_PATTERN_COUNT,
        SECRET_BYTES_PATTERNS, SafelistFilter, is_uuid_format,
    };

    #[test]
    fn safelist_inventory_has_expected_count() {
        assert_eq!(SAFELIST_PATTERNS.len(), SAFELIST_PATTERN_COUNT);
    }

    #[test]
    fn secret_bytes_inventory_has_expected_count() {
        assert_eq!(SECRET_BYTES_PATTERNS.len(), SECRET_BYTES_PATTERN_COUNT);
    }

    #[test]
    fn safelist_positive_examples_cover_all_categories() {
        let filter = SafelistFilter::new();
        let cases: [(&str, &[u8]); 18] = [
            ("placeholder+noun", br#"api_key = "placeholder_token""#),
            (
                "aws example key",
                br#"aws_access_key_id = "AKIA123456789EXAMPLE""#,
            ),
            ("redaction run", br#"github_token = "***REDACTED***""#),
            ("shell variable assignment", br#"password = ${DB_PASSWORD}"#),
            ("shell random command", br#"token=$(openssl rand -hex 32)"#),
            ("metadata marker value", br#"secret = changeme"#),
            ("hunter2 sample", br#"password = "hunter2""#),
            ("sequential demo string", br#"api_token = "0123456789""#),
            (
                "schema/xml namespace",
                br#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#,
            ),
            ("template variable", br#"auth_token = "{{API_TOKEN}}""#),
            (
                "localhost uri",
                br#"endpoint = "https://localhost:8443/token""#,
            ),
            ("secret-manager tag", br#"<secret>PLACEHOLDER</secret>"#),
            (
                "documentation prose marker",
                br#"for example, set this in sample config before deploy"#,
            ),
            (
                "insert/replace marker",
                br#"token = INSERT_YOUR_TOKEN_HERE"#,
            ),
            ("base64 sample literal", br#"value = "ZXhhbXBsZQ==""#),
            (
                "git conflict markers",
                b"<<<<<<< HEAD\nAPI_TOKEN=foo\n=======\nAPI_TOKEN=bar\n>>>>>>> branch\n",
            ),
            ("fixture/mock marker", br#"tests/fixtures/mock_secret.json"#),
            (
                "hash output line",
                br#"sha256: 3b83ef96387f14655fc854ddc3c6bd57b6dd65c4dbe90f1647f0f4a6d5f6c123"#,
            ),
        ];

        assert_eq!(
            cases.len(),
            SAFELIST_PATTERN_COUNT,
            "tests should cover each safelist category"
        );

        for (label, context) in cases {
            assert!(
                filter.matcher().is_match(context),
                "expected safelist match for category: {label}"
            );
        }
    }

    #[test]
    fn safelist_negative_examples_keep_realistic_secrets() {
        let filter = SafelistFilter::new();
        let negatives: [&[u8]; 6] = [
            br#"aws_access_key_id = "AKIA1234567890ABCD12""#,
            br#"github_token = "ghp_2fK9sD6nL0pQ8rT1vW3xY5zA7bC9dE1fG3hI""#,
            br#"stripe_secret_key = "stripe_live_token_51Nn3t4ABcdEfGhIjKlMnOpQrStUvWxYz012345""#,
            br#"db_password = "9f7A2kL8mN4qR1tV6xZ0cB3dF5gH7jK""#,
            br#"authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"#,
            br#"service_token = "v1.prod.2ab4ce6f77889900ddeeff1122334455""#,
        ];

        for context in negatives {
            assert!(
                !filter.matcher().is_match(context),
                "unexpected safelist match for realistic secret context: {}",
                String::from_utf8_lossy(context)
            );
        }
    }

    // -- Secret-bytes matcher tests --

    #[test]
    fn secret_bytes_positive_examples_cover_all_categories() {
        let filter = SafelistFilter::new();
        let cases: [(&str, &[u8]); 9] = [
            // [idx 0] Placeholder+noun on bare value.
            ("placeholder+noun", b"placeholder_token"),
            // [idx 1] AWS example key ID as bare value.
            ("aws example key", b"AKIA123456789EXAMPLE"),
            // [idx 2] Redaction run as bare value.
            ("redaction run", b"****REDACTED****"),
            // [idx 5] Metadata marker without assignment prefix.
            ("metadata value", b"changeme"),
            // [idx 6] hunter2 as bare value.
            ("hunter2", b"hunter2"),
            // [idx 7] Sequential digits as bare value.
            ("sequential digits", b"0123456789"),
            // [idx 9] Template variable as bare value.
            ("template var", b"{{API_TOKEN}}"),
            // [idx 13] INSERT_YOUR marker as bare value.
            ("insert marker", b"INSERT_YOUR_TOKEN_HERE"),
            // [idx 14] Base64 example literal as bare value.
            ("base64 example", b"ZXhhbXBsZQ=="),
        ];

        assert_eq!(
            cases.len(),
            SECRET_BYTES_PATTERN_COUNT,
            "tests should cover each secret-bytes category"
        );

        for (label, value) in cases {
            assert!(
                filter.secret_bytes_matcher().is_match(value),
                "expected secret-bytes safelist match for category: {label}"
            );
        }
    }

    #[test]
    fn secret_bytes_rejects_high_entropy_real_secrets() {
        let filter = SafelistFilter::new();
        let negatives: &[(&str, &[u8])] = &[
            // Real GitHub PAT.
            ("github pat", b"ghp_2fK9sD6nL0pQ8rT1vW3xY5zA7bC9dE1fG3hI"),
            // Random hex string.
            ("random hex", b"9f7A2kL8mN4qR1tV6xZ0cB3dF5gH7jK"),
            // JWT-like token.
            ("jwt", b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"),
            // AWS real-looking key.
            ("aws real key", b"AKIA1234567890ABCD12"),
            // Stripe key.
            ("stripe key", b"51Nn3t4ABcdEfGhIjKlMnOpQrStUvWxYz012345"),
            // Generic high-entropy.
            ("high entropy", b"v1.prod.2ab4ce6f77889900ddeeff1122334455"),
        ];

        for (label, value) in negatives {
            assert!(
                !filter.secret_bytes_matcher().is_match(value),
                "unexpected secret-bytes safelist match for realistic secret: {label}"
            );
        }
    }

    #[test]
    fn secret_bytes_mock_substring_does_not_suppress_real_key() {
        let filter = SafelistFilter::new();
        // Pattern 16 ("mock") is excluded from the secret-bytes set.
        // A realistic hyphenated API key containing "mock" as a segment
        // must NOT be suppressed.
        let key_with_mock_substring = b"api-mock-service-9xK2mB4qR1tV6xZ0";
        assert!(
            !filter
                .secret_bytes_matcher()
                .is_match(key_with_mock_substring),
            "pattern 16 (mock) must be excluded from secret-bytes set to avoid \
             suppressing real keys containing 'mock' as a substring"
        );
    }

    #[test]
    fn secret_bytes_metadata_values_match_without_prefix() {
        let filter = SafelistFilter::new();
        // The context-tier pattern 5 requires `[:=]\s*` prefix, but
        // the secret-bytes variant must match bare values.
        for value in &[b"changeme" as &[u8], b"todo", b"fixme", b"null"] {
            assert!(
                filter.secret_bytes_matcher().is_match(value),
                "metadata value {:?} should match in secret-bytes tier without prefix",
                std::str::from_utf8(value).unwrap()
            );
        }
    }

    #[test]
    fn secret_bytes_template_vars_cover_both_syntaxes() {
        let filter = SafelistFilter::new();
        assert!(
            filter.secret_bytes_matcher().is_match(b"${DATABASE_URL}"),
            "dollar-brace template should match"
        );
        assert!(
            filter.secret_bytes_matcher().is_match(b"{{SECRET_TOKEN}}"),
            "double-brace template should match"
        );
    }

    #[test]
    fn secret_bytes_composite_secrets_with_placeholder_segments_not_suppressed() {
        let filter = SafelistFilter::new();
        // Composite secrets containing placeholder words as hyphen/dot-separated
        // segments must NOT be suppressed. Before anchoring, `\b` would fire at
        // hyphens/dots and match the embedded placeholder word.
        let cases: &[(&str, &[u8])] = &[
            ("null segment", b"key-null-safety-9xK2mB"),
            ("test segment", b"prod-test_key-v2-abc123"),
            ("changeme segment", b"app-changeme-rotate-7fGh2k"),
            ("example segment", b"api.example.region-us-3nPq8w"),
            ("fixme segment", b"svc-fixme-config-2rTy6v"),
            ("todo segment", b"build-todo-tracker-8mLw4x"),
            ("hunter2 segment", b"db-hunter2-proxy-5cNj9e"),
            ("placeholder segment", b"auth-placeholder-init-4bKp7r"),
            ("fake segment", b"deploy-fake-canary-6wXt3m"),
            ("dummy segment", b"cache-dummy-warmup-1qRs5d"),
            ("EXAMPLE in longer key", b"AKIA123456789EXAMPLE_us_east_1"),
        ];

        for (label, value) in cases {
            assert!(
                !filter.secret_bytes_matcher().is_match(value),
                "composite secret with placeholder segment should NOT be suppressed: {label}"
            );
        }
    }

    // -- Provenance enforcement tests --
    //
    // These verify the mapping between SAFELIST_PATTERNS indices and the
    // SECRET_BYTES_PATTERNS subset stays consistent as patterns evolve.

    /// Indices from `SAFELIST_PATTERNS` that are included in `SECRET_BYTES_PATTERNS`.
    const SECRET_BYTES_INCLUDED_INDICES: &[usize] = &[0, 1, 2, 5, 6, 7, 9, 13, 14];

    /// Indices from `SAFELIST_PATTERNS` that are excluded from `SECRET_BYTES_PATTERNS`.
    const SECRET_BYTES_EXCLUDED_INDICES: &[usize] = &[3, 4, 8, 10, 11, 12, 15, 16, 17];

    #[test]
    fn all_context_patterns_have_secret_bytes_provenance() {
        let mut all: Vec<usize> = SECRET_BYTES_INCLUDED_INDICES
            .iter()
            .chain(SECRET_BYTES_EXCLUDED_INDICES.iter())
            .copied()
            .collect();
        all.sort_unstable();
        all.dedup();
        let expected: Vec<usize> = (0..SAFELIST_PATTERN_COUNT).collect();
        assert_eq!(
            all, expected,
            "union of included + excluded must cover 0..SAFELIST_PATTERN_COUNT"
        );
    }

    #[test]
    fn secret_bytes_provenance_lists_are_disjoint() {
        for &idx in SECRET_BYTES_INCLUDED_INDICES {
            assert!(
                !SECRET_BYTES_EXCLUDED_INDICES.contains(&idx),
                "index {idx} appears in both included and excluded lists"
            );
        }
    }

    #[test]
    fn secret_bytes_included_count_matches_pattern_count() {
        assert_eq!(
            SECRET_BYTES_INCLUDED_INDICES.len(),
            SECRET_BYTES_PATTERN_COUNT,
            "included indices length must equal SECRET_BYTES_PATTERN_COUNT"
        );
    }

    // -- UUID-format quick-reject tests --

    #[test]
    fn uuid_reject_matches_rfc_examples() {
        let cases: &[(&str, &[u8])] = &[
            // RFC 9562 §5.9 — Nil UUID.
            ("nil", b"00000000-0000-0000-0000-000000000000"),
            // RFC 9562 §5.10 — Max UUID.
            ("max", b"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"),
            // RFC 9562 / RFC 4122 running example — UUIDv1.
            ("v1 rfc9562", b"f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
            // RFC 4122 Appendix B — UUIDv1 output.
            ("v1 rfc4122", b"7d444840-9dc0-11d1-b245-5ffdce74fad2"),
            // RFC 4122 Appendix B — UUIDv3 from "www.widgets.com".
            ("v3", b"e902893a-9d22-3c7e-a7b8-d6e313b71d9f"),
            // uuid crate docs — UUIDv4.
            ("v4", b"67e55044-10b1-426f-9247-bb680e5fe0c8"),
            // RFC 4122 Appendix C — DNS namespace UUID.
            ("dns namespace", b"6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
            // RFC 4122 Appendix C — URL namespace UUID.
            ("url namespace", b"6ba7b811-9dad-11d1-80b4-00c04fd430c8"),
            // Microsoft GUID — mixed case (uppercase).
            ("ms guid", b"6B29FC40-CA47-1067-B31D-00DD010662DA"),
        ];

        for (label, value) in cases {
            assert!(
                is_uuid_format(value),
                "expected is_uuid_format to match RFC example: {label}"
            );
        }
    }

    #[test]
    fn uuid_reject_rejects_non_uuids() {
        let cases: &[(&str, &[u8])] = &[
            // 32-char hex without hyphens (MD5-like — must NOT match).
            ("32-char hex", b"f81d4fae7dec11d0a76500a0c91e6bf6"),
            // GitHub PAT.
            ("github pat", b"ghp_2fK9sD6nL0pQ8rT1vW3xY5zA7bC9dE1fG3hI"),
            // AWS key.
            ("aws key", b"AKIA1234567890ABCD12"),
            // Stripe key.
            ("stripe key", b"sk_test_51Nn3t4ABcdEfGhIjKlMnOpQrStUvWxYz"),
            // Wrong segment length (35 chars — one short).
            ("35 chars", b"f81d4fae-7dec-11d0-a765-00a0c91e6bf"),
            // Non-hex character in first segment.
            ("non-hex char", b"g81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
            // Missing a hyphen (fused second+third segments).
            ("missing hyphen", b"f81d4fae-7dec11d0-a765-00a0c91e6bf6"),
            // Empty string.
            ("empty", b""),
            // Short string.
            ("short", b"abc"),
        ];

        for (label, value) in cases {
            assert!(
                !is_uuid_format(value),
                "unexpected is_uuid_format match for non-UUID: {label}"
            );
        }
    }

    #[test]
    fn uuid_reject_anchoring_prevents_substring_match() {
        // Composite secrets containing a UUID substring must NOT match.
        // Full-value length check (36 bytes) prevents the TruffleHog #1953 pattern.
        let cases: &[(&str, &[u8])] = &[
            ("prefix", b"prefix-f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
            ("suffix", b"f81d4fae-7dec-11d0-a765-00a0c91e6bf6-suffix"),
            (
                "plaid-style",
                b"access-sandbox-67e55044-10b1-426f-9247-bb680e5fe0c8",
            ),
        ];

        for (label, value) in cases {
            assert!(
                !is_uuid_format(value),
                "is_uuid_format must not match composite secret with UUID substring: {label}"
            );
        }
    }
}
