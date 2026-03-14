//! Secret span extraction from regex captures.

/// Extracts the secret span from a regex match using capture group logic.
///
/// Many rules match more context than the actual secret (e.g., `KEY_([a-z0-9]+)`
/// matches `KEY_abc123` but the secret is just `abc123`). This function extracts
/// the narrowest meaningful span for deduplication and reporting.
///
/// # Priority
/// 1. **Configured group**: If `secret_group` is set and that group matched
///    non-empty content, use it. This allows rules with unconventional layouts.
/// 2. **First non-empty capture group**: Scan groups 1..N and use the first
///    one with non-empty content. This handles rules with alternation where
///    different groups fire depending on input (e.g., `curl-auth-header` has
///    8 groups for different auth types, only one fires per match).
/// 3. **Full match fallback**: Otherwise, use group 0 (the entire match).
///
/// Groups that did not participate in the match (`None`) or captured an empty
/// span are skipped, because some patterns have optional groups that may not
/// capture meaningful content (e.g., `([A-Z]*)` matching an empty string).
///
/// # Arguments
/// - `captures`: The regex Captures from a successful match.
/// - `secret_group`: Optional configured group index from `RuleSpec::secret_group`.
///
/// # Returns
/// `(start, end)` byte offsets of the secret span relative to the search haystack.
/// These offsets are in the same coordinate space as `Captures::get(0)`.
///
/// # Panics
/// Panics if group 0 does not exist (impossible for a successful match).
#[cfg(test)]
#[inline]
pub(crate) fn extract_secret_span(
    captures: &regex::bytes::Captures<'_>,
    secret_group: Option<u16>,
) -> (usize, usize) {
    // Priority 1: Use configured secret_group if set.
    if let Some(gi) = secret_group {
        let group_idx = gi as usize;
        if let Some(m) = captures.get(group_idx) {
            if m.start() < m.end() {
                return (m.start(), m.end());
            }
            // Group exists but matched empty - fall through to other priorities.
        } else {
            // Configured group does not exist in this regex. This indicates a rule
            // configuration error that should have been caught by RuleSpec::assert_valid().
            debug_assert!(
                false,
                "secret_group {} does not exist in regex (only {} groups)",
                group_idx,
                captures.len()
            );
        }
    }

    // Priority 2: Use the first non-empty capture group (1..N).
    // Gitleaks convention places the secret in group 1, but rules with
    // alternation (e.g., curl-auth-header) may fire a higher group.
    for gi in 1..captures.len() {
        if let Some(m) = captures.get(gi) {
            if m.start() < m.end() {
                return (m.start(), m.end());
            }
        }
    }

    // Priority 3: Fall back to full match (group 0).
    let full = captures.get(0).expect("group 0 always exists");
    (full.start(), full.end())
}

/// Extracts the secret span from reusable capture locations.
///
/// Mirrors [`extract_secret_span`] but operates on `CaptureLocations` to avoid
/// per-match allocations in hot paths.
///
/// `has_secret_group_override` is carried separately so all `u16` values
/// (including `u16::MAX`) remain valid capture-group indices.
#[inline]
pub(crate) fn extract_secret_span_locs_raw(
    locs: &regex::bytes::CaptureLocations,
    secret_group_raw: u16,
    has_secret_group_override: bool,
) -> (usize, usize) {
    if has_secret_group_override {
        let group_idx = secret_group_raw as usize;
        if let Some((start, end)) = locs.get(group_idx) {
            if start < end {
                return (start, end);
            }
        } else {
            debug_assert!(
                false,
                "secret_group {} does not exist in regex (only {} groups)",
                group_idx,
                locs.len()
            );
        }
    }

    // Fast path: group 1 (covers >90% of rules).
    if let Some((start, end)) = locs.get(1) {
        if start < end {
            return (start, end);
        }
    }

    // Slow path: scan groups 2..N for the first non-empty capture.
    for gi in 2..locs.len() {
        if let Some((start, end)) = locs.get(gi) {
            if start < end {
                return (start, end);
            }
        }
    }

    let (start, end) = locs.get(0).expect("group 0 always exists");
    (start, end)
}
