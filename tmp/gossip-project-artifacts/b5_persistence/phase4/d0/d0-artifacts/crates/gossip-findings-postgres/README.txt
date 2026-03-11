D0 findings Postgres schema plan

This crate locks the normalized relational shape before migrations:
- findings     : stable finding identity
- occurrences  : version + span identity
- observations : policy-scoped detection/provenance

The key rule is that policy-specific state lives only in observations.
Occurrences intentionally omit policy_hash.

Migrations land in D1.
FindingsSink implementation lands in D2.
