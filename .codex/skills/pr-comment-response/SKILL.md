---
name: pr-comment-response
description: Respond to PR review comments by building the smallest proof that confirms or refutes the claim before changing code or docs — never blindly trust a reviewer
---

# PR Comment Response

Respond to pull request review comments using a verify-first approach. Never blindly accept reviewer suggestions — build the smallest proof that can confirm or refute the claim before changing code or docs.

## When to Use

- After receiving code review comments on a PR
- When a reviewer claims code has a bug, edge case, or incorrect behavior
- When you need to systematically work through multiple PR comments
- Invoke with: `/pr-comment-response <PR-number>`

## Core Principle

**Reviewers can be wrong.** Treat every correctness claim as a hypothesis, not a fact. The workflow is:

1. Read the comment
2. Understand the claim
3. Choose the smallest proof that could decide it
4. Run that proof
5. Change code or docs only if the proof justifies it
6. Respond with evidence

## Workflow

### Step 1: Fetch PR Comments

```bash
# Get all review comments on the PR
gh pr view <PR-number> --json reviews,comments
gh api repos/{owner}/{repo}/pulls/<PR-number>/comments
```

Collect every comment. Categorize each one:

| Category | Action |
|----------|--------|
| **Bug report** | Full verify-first workflow (Steps 2-6) |
| **Invariant / assertion-strength claim** | Targeted boundary proof plus code-path audit |
| **Style/naming suggestion** | Evaluate on merit, apply if reasonable |
| **Question / clarification** | Reply with explanation |
| **Refactor suggestion** | Evaluate, apply if it improves clarity without risk |
| **Nitpick** | Apply if trivial and correct |

**Focus the verify-first workflow on bug reports and correctness claims.** These are the comments where blind trust is most dangerous.

### Step 2: Analyze Each Bug Claim

For each comment claiming a bug or incorrect behavior:

1. **Read the code** the comment refers to — understand it fully before proceeding
2. **Identify the claim** — what specific behavior does the reviewer say is wrong?
3. **Identify the trigger** — what input, state, or condition would expose the bug?
4. **Assess plausibility** — does the claim make logical sense given the code?

Document your analysis before building any proof:

```markdown
### Comment: [reviewer quote or summary]
- **File**: path/to/file.rs:LINE
- **Claim**: [what the reviewer says is wrong]
- **Trigger condition**: [input/state that would expose the bug]
- **Plausibility**: [high/medium/low — your initial assessment and why]
- **Best proof form**: [failing test / boundary test + code-path audit / doc-only verification]
```

### Step 3: Construct the Smallest Discriminating Proof

Pick the lightest proof that can separate "reviewer is right" from "reviewer is wrong":

| Claim shape | Preferred proof |
|-------------|-----------------|
| Behavioral bug | A failing test that directly targets the claimed trigger |
| Boundary or invariant-strength concern | The smallest boundary test that distinguishes the competing claims, plus a code-path audit if control flow matters |
| Docs / wording mismatch | Verify against implementation and update docs only if the reviewer is right |

If the right proof is a test, it should:

- Use the exact trigger condition the reviewer described (or a minimal reproduction)
- Assert the **correct** behavior (what the code *should* do)
- Be placed in the appropriate test module for the file under review
- Have a clear, descriptive name describing **the behavior being tested** — never reference the PR comment, reviewer, or call it a "regression test"

```rust
#[test]
fn handles_empty_input_without_panic() {
    let result = function_under_review(&[]);
    assert!(result.is_ok(), "empty input should not panic");
}
```

**Do NOT touch the production code yet.**

### Step 4: Run the Proof

Run the proof you chose.

If the proof includes a test:

```bash
cargo test <test_name> -- --nocapture
```

**Three outcomes matter:**

#### Bug confirmed

The proof shows the implementation is wrong. Proceed to Step 5.

Record:
```markdown
- **Verdict**: CONFIRMED — [failing test, trace, or boundary proof]
```

#### Code is correct, but docs or wording are misleading

Do not change the implementation. Fix only the docs or comments that created the confusion.

Record:
```markdown
- **Verdict**: DOCS ONLY — implementation is correct, wording was misleading
- **Evidence**: [test, trace, or code-path proof]
```

#### Claim not reproduced

The code already handles this case correctly. **Do not change the code.**

If you wrote a diagnostic test and it passes, **delete it** unless it adds durable coverage for a realistic future risk.

Record:
```markdown
- **Verdict**: NOT REPRODUCED — code already handles this correctly
- **Verification artifact**: removed or not kept if it was diagnostic only
- **Response**: [draft reply to reviewer explaining why the code is correct]
```

Skip to Step 6 for this comment.

### Step 5: Apply the Minimal Change Supported by the Proof

Now — and only now — make the smallest change the evidence supports:

1. If the implementation is wrong, make the **minimal code change** needed to satisfy the proof.
2. If only the wording is wrong, make the **minimal doc or comment change** needed to match reality.
3. Re-run the specific proof to confirm the change is correct.
4. Run broader checks if code changed.

```bash
# Confirm the fix
cargo test <test_name> -- --nocapture

# Check for regressions
cargo test
```

If broader checks fail, investigate — the fix may have been too broad or revealed a deeper issue.

### Step 6: Respond to the Reviewer

Draft responses for each comment:

**For confirmed bugs:**
```markdown
Good catch! Confirmed — added a test (`test_name`) that reproduces this.
Fixed in [commit SHA]. The issue was [brief explanation].
```

**For docs-only corrections:**
```markdown
I checked this against the current implementation. The code path is correct, but the wording was misleading.
Clarified in [commit SHA] so the docs now match the actual behavior.
```

**For unconfirmed claims:**
```markdown
I investigated this with a targeted proof for the scenario you described.
The current code already handles it correctly — [brief explanation of why the code is correct].
Let me know if I'm missing something.
```

**For non-bug comments (style, refactor, questions):**
Address directly without the test workflow.

## Handling Multiple Comments

When a PR has many comments:

1. **Triage first** — categorize all comments before acting on any
2. **Prioritize bug claims** — handle these with full verify-first workflow
3. **Batch style/nitpick fixes** — apply these together in one pass
4. **Group related comments** — if multiple comments point at the same underlying issue, write one comprehensive test

## Output Format

After processing all comments, produce a summary:

```markdown
## PR Comment Response Summary — PR #<number>

### Claims Investigated

| # | Comment | File | Verdict | Proof | Fix |
|---|---------|------|---------|-------|-----|
| 1 | [summary] | path:line | CONFIRMED | failing test `test_name` | commit SHA |
| 2 | [summary] | path:line | DOCS ONLY | code-path audit + targeted proof | commit SHA |
| 3 | [summary] | path:line | NOT REPRODUCED | verified & removed | N/A |

### Other Changes

- [Style fix]: renamed `foo` to `bar` per reviewer suggestion
- [Refactor]: extracted helper function for clarity
- [Reply]: explained why X is intentional

### Test Results

- New tests added: N
- All tests passing: yes/no
- Regressions found: none / [details]
```

## Anti-Patterns to Avoid

- **Blind application**: Never change code just because a reviewer said to
- **Skipping the proof**: Always produce evidence before changing code or docs
- **Using a heavyweight test when a smaller proof would decide it**: Prefer the lightest artifact that discriminates between the competing claims
- **Fixing without confirmation**: If your proof does not show the implementation is wrong, don't "fix" it
- **Over-scoping fixes**: Fix only what the proof shows is wrong, nothing more
- **Keeping diagnostic tests**: If a verification artifact only proved the reviewer wrong, remove it unless it adds durable value
- **Naming tests after the review**: Never name a test "regression_for_pr_comment" or similar. Name it after the behavior it verifies.
- **Arguing without evidence**: If you disagree with a reviewer, show a passing test, don't just assert correctness

## Related Skills

- `/test-strategy` - Choose appropriate test type (unit, property, fuzz, Kani)
- `/security-reviewer` - For security-related review comments
- `/bench-compare` - If reviewer flags a performance issue
