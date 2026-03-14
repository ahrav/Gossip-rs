# Contributing notes

## Source architecture guardrail

Epic 1 removed the legacy driver-based source execution model.

Do not add new code that revives the removed driver stack. New source work must
be expressed through the family-based connector contracts under
`gossip-contracts::connector`:

- shared paging vocabulary in `connector::common`
- ordered content sources in `connector::ordered`
- Git discovery / mirror / execution in `connector::git`

If you are adding a new source and it does not fit one of the current families,
add a new source-family contract instead of smuggling the old design back in.

Before sending a change, run:

```bash
python3 scripts/check_no_legacy_driver_stack.py
```

That check intentionally fails if the removed driver-stack identifiers are
reintroduced anywhere in the repo.
