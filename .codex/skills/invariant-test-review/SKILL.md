---
name: invariant-test-review
description: Review tests to ensure they actually prove the claimed invariant, especially state-machine, simulation, oracle, and regression tests where extra setup, missing negative paths, or order-sensitive comparisons can hide the real signal
user-invocable: true
---

# Invariant Test Review

Review tests with one question: **does this test actually prove the property it
claims to prove?**

This skill is for subtle tests where the risk is not "missing coverage" in the
abstract, but "the test passes without isolating the intended invariant."

## When to Use

- When a PR adds or rewrites tests for coordination, state machines, or
  multi-step workflows
- When a reviewer says "this test does not isolate the invariant"
- When oracle or comparable-state assertions aggregate many fields
- When unordered collections appear in test comparisons
- When terminal-state, rejection, replay, or idempotency behavior matters
- When a regression test feels plausible but may be proving the wrong thing

## When NOT to Use

- Trivial input/output tests with one obvious assertion and no hidden state
- Broad test-planning work where the main question is test type selection
  rather than proof strength
- Pure documentation review without test changes

## Core Principle

A test only proves what its setup, observation surface, and assertions uniquely
force. If the test can pass because of unrelated setup, missing negative cases,
or a lossy comparator, it is weaker than it looks.

## Workflow

### 1. State the Claimed Invariant

Rewrite the test's purpose as one precise sentence.

Good:
- `stale lease checkpoints are rejected`
- `terminal failed runs never become active again`
- `oracle comparison ignores spawned order but preserves child identity`

Weak:
- `covers eviction`
- `tests failure handling`
- `checks drift`

If you cannot name the invariant in one sentence, the test is underspecified.

### 2. Identify the Minimal Trigger

Ask:

- What smallest input or state transition should make this test flip from pass
  to fail?
- Which setup steps are required for that transition?
- Which setup steps are merely cargo cult from another test?

Delete or inline anything that does not participate in the invariant.

### 3. Audit the Observation Surface

The assertion must observe the property directly.

- For rejection behavior: assert the specific error or state rejection, not
  just "operation returned false"
- For terminal-state behavior: assert irreversibility explicitly
- For replay/idempotency behavior: assert the cached or repeated result, not
  only overall success
- For eviction/order/drift behavior: inspect the comparable state, not a loose
  side effect

If the assertion only checks a proxy, call that out.

### 4. Add the Discriminating Twin

When the real question is "is this assertion strong enough?", add the smallest
paired case that distinguishes the competing claims:

- Happy path + negative path
- Allowed boundary + rejected boundary
- Ordered input + permuted input
- Fresh lease + stale lease
- Pre-terminal transition + post-terminal transition

For terminal, rejection, replay, and idempotency rules, the negative or
boundary twin is usually mandatory.

### 5. Audit Oracle and Comparator Semantics

Many misleading tests come from a comparator that is wrong, not the system
under test.

Check for:

- Order-sensitive `Vec` equality over logically unordered state
- Snapshots that omit the field the invariant depends on
- Comparable wrappers that normalize too much or too little
- Equality checks that conflate identity with presentation order

If order is irrelevant, compare setwise or sort explicitly before asserting.

### 6. Confirm the Failure Mode

Ask the final question:

`If the code were wrong in exactly the way we care about, would this test fail for that reason?`

If the answer is "not sure" or "only indirectly," the test needs revision.

## Red Flags

- The test name claims one invariant, but the assertion only checks generic
  success
- Setup acquires leases, cursors, or resources that are never used by the
  assertion
- A "regression test" duplicates a larger scenario instead of isolating the bug
- Terminal or rejection semantics are tested only on the happy path
- Comparable-state assertions use order-sensitive equality for unordered data
- The test could fail because of an unrelated precondition before it reaches the
  behavior under review

## Review Output

Return a short report in this format:

```markdown
## Invariant Test Review: [test name or file]

- **Claimed invariant**: [one sentence]
- **Minimal trigger**: [smallest state/input that matters]
- **Observation surface**: [what the assertion actually observes]

### Findings

1. [Issue]: [why the current test is weaker than it looks]
2. [Issue]: [missing twin, confounder, or comparator problem]

### Recommended Rewrite

- Remove: [vestigial setup]
- Add: [negative-path or boundary twin]
- Normalize: [unordered state before comparison]
- Assert: [the direct property instead of a proxy]
```

## Related Skills

- `/test-strategy` — choose the right test form once the invariant is clear
- `/sim-review` — review DST compatibility and simulation-specific constraints
- `/pr-comment-response` — verify reviewer bug claims with the smallest proof
