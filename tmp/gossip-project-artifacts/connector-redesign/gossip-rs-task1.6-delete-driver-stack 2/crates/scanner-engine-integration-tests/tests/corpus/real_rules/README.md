# Real Rules Fixture Corpus

Synthetic, non-sensitive fixtures for the real ruleset harness (Mode 2).
This corpus is intentionally small and representative; expand only with
well-motivated additions.

## Layout

| Component | Location | Purpose |
|---|---|---|
| Fixtures | `fixtures/` | Curated sample files with synthetic secrets |
| Expected baseline | `expected/findings.json` | Normalized findings (golden) |
| README | `README.md` | Corpus rationale and structure |

## Safety

- All tokens are synthetic and safe.
- Values are intentionally fake and non-functional.
- Do not add real secrets to this corpus.
