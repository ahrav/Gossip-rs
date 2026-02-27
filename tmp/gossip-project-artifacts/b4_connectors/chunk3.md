## 1) Scope

- Phase III connector contract (Boundary 4), **Chunk 3**
- Implement the **page-level validator** as a pure function:
  - `validate_page(spec, input_cursor, items, next_cursor) -> Result<(), PageValidationError>`

- Include **unit tests for the validator** (fast, pure, local invariants only)
- Out of scope for this chunk:
  - Property/resumption/determinism harness (Chunk 4)
  - Full runtime wiring across the worker pipeline (but I’ll note exactly where the call must go)

---

## 2) Assumptions

These are the only assumptions the code below makes about your current connector boundary types:

- `EnumerationSpec` has `start: ItemKey` and `end: ItemKey` with the range interpreted as **`[start, end)`**.
- `Cursor` has `last_key: Option<ItemKey>`:
  - `None` means “start from the shard start”
  - `Some(k)` means “resume **strictly after** `k`” (this matches the “start after cursor.last_key must work” requirement).

- `ScanItem` has `item_key: ItemKey`.
- `ItemKey: Ord + AsRef<[u8]>` (lex order by bytes).
- You already have (or are willing to add) a `blake3` dependency for hash-only diagnostics.

If your `Cursor.last_key` is not `Option<ItemKey>`, you’ll need to reconcile semantics first. This validator is deliberately opinionated about the “resume after last_key” meaning.

---

## 3) Decision

### Chosen approach (what I coded)

- A **strict, safety-focused page validator** that enforces local invariants:
  - membership (shard safety)
  - ordering
  - cursor monotonicity
  - cursor consistency with returned items
  - empty-page cursor behavior
  - plus one extra safety rule that follows from “resume after last_key”:
    - if `input_cursor.last_key = Some(k)`, then the **first returned key must be strictly greater than `k`**

Why: this catches contract bugs early, prevents infinite loops and duplicate re-enumeration, and hardens the “token can fail” story.

### Alternative (not implemented)

- A more permissive validator that allows returned keys `>= input_cursor.last_key` (inclusive resume).
  - Pro: fewer false positives if connectors are sloppy or view is weak.
  - Con: makes “resume after last_key” ambiguous, allows duplicate pages, and makes liveness failures easier.

Given your stated goal (“hard gate”), permissive semantics are a trap.

---

## 4) Invariants and failure behavior

Validator enforces:

- **Spec sanity**
  - `start <= end`

- **Cursor range sanity**
  - `cursor.last_key` and `next_cursor.last_key` (if present) must be within `[start, end]` (note: end inclusive for cursors)

- **Membership**
  - each returned `item_key` must be in `[start, end)`

- **Ordering**
  - non-decreasing by key

- **Resumption-by-key local implication**
  - if `input_cursor.last_key = Some(k)` and items returned, `items[0].key > k`

- **Cursor consistency**
  - if items returned, `next_cursor.last_key` must exist and be `>= last_item_key`

- **Cursor monotonic**
  - if `input_cursor.last_key = Some(k)` then `next_cursor.last_key >= k`

- **Empty-page rule**
  - if `items` is empty, `next_cursor.last_key` must equal `input_cursor.last_key` (no advancement)

Failure behavior rule:

- Any violation returns a **typed `PageValidationError`** that contains only **hashes**, never raw keys/tokens.

---

## 5) Tests

Included unit tests (fast, deterministic):

- Reject out-of-range item keys
- Reject unsorted pages
- Reject returning an item not strictly after `input_cursor.last_key`
- Reject `next_cursor.last_key < last_item_key`
- Reject cursor regression (`next_cursor.last_key < input_cursor.last_key`)
- Reject empty page that advances cursor
- Accept a valid page

Property tests (token corruption, resumability, determinism) are intentionally **not** in this chunk (that’s Chunk 4).

---

## 6) Implementation notes

- The core logic is in a generic helper `validate_page_range(...)` so tests can use `Vec<u8>` keys without depending on your real connector structs.
- The public `validate_page(...)` is just a wrapper over your real types.
- Diagnostics use `ToxicDigest`:
  - stores `len` + `blake3` hash
  - prints only first 8 bytes of the hash

Perf:

- `O(n)` comparisons, `O(n)` hash computations in the failing path only (on success, only a few digests are built when checking spec/cursors? actually it hashes only on error; the normal path does no hashing except in some checks where we precompute start/end digests for error construction. I kept hashing _only when building an error_.)

---

## 7) Code

### `crates/gossip-contracts/src/connector/page_validator.rs`

```rust
//! Page-level connector contract validator.
//!
//! This module implements **safety** checks that are local to a single
//! `enumerate_page()` call.
//!
//! It is intended to be a hard gate in:
//! - connector conformance tests (Chunk 4 harness will lean on it)
//! - worker runtime enumeration path (Phase IV enumeration path must call it)
//!
//! The validator is deliberately **pure** (no logging, no I/O).
//! Any diagnostic data is **hash-only**. Never include raw keys/refs/tokens.

use core::fmt;

use super::{Cursor, EnumerationSpec, ScanItem};

/// A view of an item that has an ordered key.
///
/// This exists so we can unit-test the validator using simple structs without
/// depending on concrete connector types.
pub trait PageItem<K> {
    fn item_key(&self) -> &K;
}

impl PageItem<super::ItemKey> for ScanItem {
    fn item_key(&self) -> &super::ItemKey {
        &self.item_key
    }
}

/// A hash-only representation of toxic bytes (keys/tokens/refs).
///
/// Safe to include in errors/logs/metrics.
/// Never include raw bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ToxicDigest {
    len: usize,
    hash: [u8; 32],
}

impl ToxicDigest {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let h = blake3::hash(bytes);
        Self {
            len: bytes.len(),
            hash: *h.as_bytes(),
        }
    }

    pub fn of<K: AsRef<[u8]> + ?Sized>(k: &K) -> Self {
        Self::of_bytes(k.as_ref())
    }
}

impl fmt::Debug for ToxicDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for ToxicDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "len={}, hash=", self.len)?;
        // Print only a prefix of the digest for readability.
        for b in &self.hash[..8] {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorWhich {
    Input,
    Next,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageValidationViolation {
    SpecRangeInvalid,
    InputCursorOutOfRange,
    NextCursorOutOfRange,
    ItemKeyOutOfRange,
    ItemsNotOrdered,
    ItemsNotAfterCursor,
    NextCursorMissing,
    NextCursorBehindLastItem,
    CursorRegressed,
    EmptyPageCursorAdvanced,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageValidationDetails {
    Spec {
        start: ToxicDigest,
        end: ToxicDigest,
    },

    CursorOutOfRange {
        which: CursorWhich,
        key: ToxicDigest,
        start: ToxicDigest,
        end: ToxicDigest,
    },

    ItemOutOfRange {
        index: usize,
        key: ToxicDigest,
        start: ToxicDigest,
        end: ToxicDigest,
    },

    NotOrdered {
        index: usize,
        prev: ToxicDigest,
        next: ToxicDigest,
    },

    NotAfterCursor {
        cursor: ToxicDigest,
        first_item: ToxicDigest,
    },

    NextCursorBehindLastItem {
        next_cursor: ToxicDigest,
        last_item: ToxicDigest,
    },

    CursorRegressed {
        input: ToxicDigest,
        next: ToxicDigest,
    },

    EmptyCursorAdvanced {
        input: Option<ToxicDigest>,
        next: Option<ToxicDigest>,
    },

    NextCursorMissing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageValidationError {
    pub violation: PageValidationViolation,
    pub details: PageValidationDetails,
}

impl fmt::Display for PageValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PageValidationDetails as D;
        use PageValidationViolation as V;

        match (&self.violation, &self.details) {
            (V::SpecRangeInvalid, D::Spec { start, end }) => {
                write!(f, "invalid spec range: start={start}, end={end}")
            }

            (V::InputCursorOutOfRange, D::CursorOutOfRange { key, start, end, .. }) => {
                write!(
                    f,
                    "input cursor out of range: key={key}, allowed=[{start}, {end}]"
                )
            }

            (V::NextCursorOutOfRange, D::CursorOutOfRange { key, start, end, .. }) => {
                write!(
                    f,
                    "next cursor out of range: key={key}, allowed=[{start}, {end}]"
                )
            }

            (V::ItemKeyOutOfRange, D::ItemOutOfRange { index, key, start, end }) => {
                write!(
                    f,
                    "item key out of range at index {index}: key={key}, allowed=[{start}, {end})"
                )
            }

            (V::ItemsNotOrdered, D::NotOrdered { index, prev, next }) => {
                write!(
                    f,
                    "items not ordered at index {index}: prev={prev}, next={next}"
                )
            }

            (V::ItemsNotAfterCursor, D::NotAfterCursor { cursor, first_item }) => {
                write!(
                    f,
                    "items must start strictly after input cursor: cursor={cursor}, first_item={first_item}"
                )
            }

            (V::NextCursorMissing, D::NextCursorMissing) => {
                write!(f, "next_cursor.last_key is missing but items were returned")
            }

            (
                V::NextCursorBehindLastItem,
                D::NextCursorBehindLastItem {
                    next_cursor,
                    last_item,
                },
            ) => {
                write!(
                    f,
                    "next_cursor.last_key is behind last item: next_cursor={next_cursor}, last_item={last_item}"
                )
            }

            (V::CursorRegressed, D::CursorRegressed { input, next }) => {
                write!(f, "cursor regressed: input={input}, next={next}")
            }

            (V::EmptyPageCursorAdvanced, D::EmptyCursorAdvanced { input, next }) => {
                write!(
                    f,
                    "empty page advanced cursor: input={input:?}, next={next:?}"
                )
            }

            _ => write!(f, "page validation violation: {:?}", self.violation),
        }
    }
}

impl std::error::Error for PageValidationError {}

fn opt_key_eq<K: Ord>(a: Option<&K>, b: Option<&K>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Validate a page given an explicit key range.
///
/// Assumed semantics:
/// - `input_last_key` (when present) is the **last fully returned** key.
/// - A correct connector must return items with keys **strictly greater** than
///   `input_last_key`.
/// - Returned item keys must satisfy `start <= key < end`.
/// - Cursor keys (when present) must satisfy `start <= key <= end`.
///
/// Pure and side-effect free.
pub fn validate_page_range<K, I>(
    start: &K,
    end: &K,
    input_last_key: Option<&K>,
    items: &[I],
    next_last_key: Option<&K>,
) -> Result<(), PageValidationError>
where
    K: Ord + AsRef<[u8]>,
    I: PageItem<K>,
{
    // Spec sanity.
    if start > end {
        return Err(PageValidationError {
            violation: PageValidationViolation::SpecRangeInvalid,
            details: PageValidationDetails::Spec {
                start: ToxicDigest::of(start),
                end: ToxicDigest::of(end),
            },
        });
    }

    // Cursor range sanity (cursor may be == end).
    if let Some(k) = input_last_key {
        if k < start || k > end {
            return Err(PageValidationError {
                violation: PageValidationViolation::InputCursorOutOfRange,
                details: PageValidationDetails::CursorOutOfRange {
                    which: CursorWhich::Input,
                    key: ToxicDigest::of(k),
                    start: ToxicDigest::of(start),
                    end: ToxicDigest::of(end),
                },
            });
        }
    }

    if let Some(k) = next_last_key {
        if k < start || k > end {
            return Err(PageValidationError {
                violation: PageValidationViolation::NextCursorOutOfRange,
                details: PageValidationDetails::CursorOutOfRange {
                    which: CursorWhich::Next,
                    key: ToxicDigest::of(k),
                    start: ToxicDigest::of(start),
                    end: ToxicDigest::of(end),
                },
            });
        }
    }

    // Membership.
    for (i, item) in items.iter().enumerate() {
        let k = item.item_key();
        if k < start || k >= end {
            return Err(PageValidationError {
                violation: PageValidationViolation::ItemKeyOutOfRange,
                details: PageValidationDetails::ItemOutOfRange {
                    index: i,
                    key: ToxicDigest::of(k),
                    start: ToxicDigest::of(start),
                    end: ToxicDigest::of(end),
                },
            });
        }
    }

    // Ordering: non-decreasing.
    for (i, pair) in items.windows(2).enumerate() {
        let prev = pair[0].item_key();
        let next = pair[1].item_key();
        if prev > next {
            return Err(PageValidationError {
                violation: PageValidationViolation::ItemsNotOrdered,
                details: PageValidationDetails::NotOrdered {
                    index: i,
                    prev: ToxicDigest::of(prev),
                    next: ToxicDigest::of(next),
                },
            });
        }
    }

    // Empty page rule: cursor must not advance.
    if items.is_empty() {
        if !opt_key_eq(input_last_key, next_last_key) {
            return Err(PageValidationError {
                violation: PageValidationViolation::EmptyPageCursorAdvanced,
                details: PageValidationDetails::EmptyCursorAdvanced {
                    input: input_last_key.map(ToxicDigest::of),
                    next: next_last_key.map(ToxicDigest::of),
                },
            });
        }
        return Ok(());
    }

    // If items were returned, next cursor must exist.
    let next_k = match next_last_key {
        Some(k) => k,
        None => {
            return Err(PageValidationError {
                violation: PageValidationViolation::NextCursorMissing,
                details: PageValidationDetails::NextCursorMissing,
            });
        }
    };

    // Items must start strictly after the input cursor, when present.
    if let Some(in_k) = input_last_key {
        let first = items[0].item_key();
        if first <= in_k {
            return Err(PageValidationError {
                violation: PageValidationViolation::ItemsNotAfterCursor,
                details: PageValidationDetails::NotAfterCursor {
                    cursor: ToxicDigest::of(in_k),
                    first_item: ToxicDigest::of(first),
                },
            });
        }
    }

    // Cursor monotonicity relative to input.
    if let Some(in_k) = input_last_key {
        if next_k < in_k {
            return Err(PageValidationError {
                violation: PageValidationViolation::CursorRegressed,
                details: PageValidationDetails::CursorRegressed {
                    input: ToxicDigest::of(in_k),
                    next: ToxicDigest::of(next_k),
                },
            });
        }
    }

    // Cursor consistency with returned items.
    let last_item_key = items.last().expect("items non-empty").item_key();
    if next_k < last_item_key {
        return Err(PageValidationError {
            violation: PageValidationViolation::NextCursorBehindLastItem,
            details: PageValidationDetails::NextCursorBehindLastItem {
                next_cursor: ToxicDigest::of(next_k),
                last_item: ToxicDigest::of(last_item_key),
            },
        });
    }

    Ok(())
}

/// Convenience wrapper for your concrete connector types.
///
/// Call this from:
/// - connector conformance tests
/// - worker runtime enumeration path
pub fn validate_page(
    spec: &EnumerationSpec,
    input_cursor: &Cursor,
    items: &[ScanItem],
    next_cursor: &Cursor,
) -> Result<(), PageValidationError> {
    validate_page_range(
        &spec.start,
        &spec.end,
        input_cursor.last_key.as_ref(),
        items,
        next_cursor.last_key.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Item {
        k: Vec<u8>,
    }

    impl PageItem<Vec<u8>> for Item {
        fn item_key(&self) -> &Vec<u8> {
            &self.k
        }
    }

    fn v(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn rejects_out_of_range_item_key() {
        let start = v("a");
        let end = v("c");
        let items = vec![Item { k: v("c") }]; // == end is out of [start,end)

        let err = validate_page_range(&start, &end, None, &items, Some(&start)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::ItemKeyOutOfRange);
    }

    #[test]
    fn rejects_unsorted_items() {
        let start = v("a");
        let end = v("z");
        let items = vec![Item { k: v("b") }, Item { k: v("a") }];

        let err = validate_page_range(&start, &end, None, &items, Some(&end)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::ItemsNotOrdered);
    }

    #[test]
    fn rejects_item_not_after_cursor() {
        let start = v("a");
        let end = v("z");
        let cursor = v("m");
        let items = vec![Item { k: v("m") }]; // not strictly after

        let err =
            validate_page_range(&start, &end, Some(&cursor), &items, Some(&cursor)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::ItemsNotAfterCursor);
    }

    #[test]
    fn rejects_next_cursor_behind_last_item() {
        let start = v("a");
        let end = v("z");
        let items = vec![Item { k: v("b") }, Item { k: v("c") }];
        let next = v("b"); // behind last item c

        let err = validate_page_range(&start, &end, None, &items, Some(&next)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::NextCursorBehindLastItem);
    }

    #[test]
    fn rejects_cursor_regression() {
        let start = v("a");
        let end = v("z");
        let input = v("m");
        let next = v("l"); // regressed
        let items = vec![Item { k: v("n") }];

        let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::CursorRegressed);
    }

    #[test]
    fn rejects_empty_page_cursor_advance() {
        let start = v("a");
        let end = v("z");
        let input = v("m");
        let next = v("n");
        let items: Vec<Item> = vec![];

        let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::EmptyPageCursorAdvanced);
    }

    #[test]
    fn accepts_valid_page() {
        let start = v("a");
        let end = v("z");
        let items = vec![Item { k: v("a") }, Item { k: v("b") }];
        let next = v("b");

        validate_page_range(&start, &end, None, &items, Some(&next)).unwrap();
    }
}
```

---

## Required integration points (no code here because I don’t have your current worker file tree)

You must call `validate_page(...)` in exactly two places:

- **Worker runtime enumeration path**:
  - immediately after `enumerate_page(...)` returns and before you enqueue/process any items
  - on `Err(PageValidationError)`, treat as **fatal contract violation** (do not retry blindly)

- **Connector conformance tests**:
  - every page emitted by a connector under test must pass `validate_page(...)`

Minimal hook you’ll need in your module tree:

- In `crates/gossip-contracts/src/connector/mod.rs` (or wherever your connector module lives):
  - `pub mod page_validator;`
  - optionally `pub use page_validator::{validate_page, PageValidationError, ...};`

---
