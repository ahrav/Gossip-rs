//! Confirm helpers for packed-pattern membership checks.

use crate::engine::rule_repr::PackedPatterns;
use memchr::memmem;

/// Returns true if any packed needle exists in the haystack.
///
/// # Preconditions
/// - `needles.offsets` indexes into `needles.bytes` and is monotonically
///   increasing. Each interval denotes one pattern.
/// - `needles` uses a prefix-sum offset table (last offset == `needles.bytes.len()`).
///
/// # Behavior
/// - Returns false when `needles` contains no patterns.
/// - Fast-paths the common single-needle case to avoid loop overhead.
pub(crate) fn contains_any_memmem(hay: &[u8], needles: &PackedPatterns) -> bool {
    let count = needles.offsets.len().saturating_sub(1);
    if count == 1 {
        let end = needles.offsets[1] as usize;
        return memmem::find(hay, &needles.bytes[..end]).is_some();
    }
    for i in 0..count {
        let start = needles.offsets[i] as usize;
        let end = needles.offsets[i + 1] as usize;
        debug_assert!(end <= needles.bytes.len());
        // SAFETY: PackedPatterns invariant guarantees offsets index into bytes.
        let needle = unsafe { needles.bytes.get_unchecked(start..end) };
        if memmem::find(hay, needle).is_some() {
            return true;
        }
    }
    false
}

/// Returns true only if every packed needle exists in the haystack.
///
/// # Preconditions
/// - `needles.offsets` indexes into `needles.bytes` and is monotonically
///   increasing. Each interval denotes one pattern.
/// - `needles` uses a prefix-sum offset table (last offset == `needles.bytes.len()`).
///
/// # Behavior
/// - Returns true when `needles` contains no patterns.
/// - Fast-paths the common single-needle case to avoid loop overhead.
pub(crate) fn contains_all_memmem(hay: &[u8], needles: &PackedPatterns) -> bool {
    let count = needles.offsets.len().saturating_sub(1);
    if count == 1 {
        let end = needles.offsets[1] as usize;
        return memmem::find(hay, &needles.bytes[..end]).is_some();
    }
    for i in 0..count {
        let start = needles.offsets[i] as usize;
        let end = needles.offsets[i + 1] as usize;
        debug_assert!(end <= needles.bytes.len());
        // SAFETY: PackedPatterns invariant guarantees offsets index into bytes.
        let needle = unsafe { needles.bytes.get_unchecked(start..end) };
        if memmem::find(hay, needle).is_none() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::rule_repr::PackedPatternsBuilder;

    fn build_packed(patterns: &[&[u8]]) -> PackedPatterns {
        let byte_len: usize = patterns.iter().map(|p| p.len()).sum();
        let mut b = PackedPatternsBuilder::with_capacity(patterns.len(), byte_len);
        for &p in patterns {
            b.push_raw(p);
        }
        b.build()
    }

    #[test]
    fn contains_any_memmem_cases() {
        let hay = b"hello world";
        let cases: &[(&str, &[&[u8]], bool)] = &[
            ("zero needles", &[], false),
            ("single needle present", &[b"world"], true),
            ("single needle absent", &[b"xyz"], false),
            ("multiple needles one present", &[b"xyz", b"world"], true),
            ("multiple needles none present", &[b"xyz", b"abc"], false),
        ];
        for &(desc, needles, expected) in cases {
            let packed = build_packed(needles);
            assert_eq!(
                contains_any_memmem(hay, &packed),
                expected,
                "contains_any_memmem failed for case: {desc}",
            );
        }
    }

    #[test]
    fn contains_all_memmem_cases() {
        let hay = b"hello world";
        let cases: &[(&str, &[&[u8]], bool)] = &[
            ("zero needles", &[], true),
            ("single needle present", &[b"hello"], true),
            ("single needle absent", &[b"xyz"], false),
            ("multiple needles all present", &[b"hello", b"world"], true),
            ("multiple needles one missing", &[b"hello", b"xyz"], false),
        ];
        for &(desc, needles, expected) in cases {
            let packed = build_packed(needles);
            assert_eq!(
                contains_all_memmem(hay, &packed),
                expected,
                "contains_all_memmem failed for case: {desc}",
            );
        }
    }
}
