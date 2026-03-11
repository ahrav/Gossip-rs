D0 + D1 findings Postgres backend foundation

This crate locks the normalized relational shape and adds forward-only,
checksum-verified migrations.

Schema model:
- findings     : stable finding identity
- occurrences  : version + span identity
- observations : policy-scoped detection/provenance

Key invariant:
- occurrences intentionally omit policy_hash
- observations intentionally include policy_hash

Migration runner properties:
- embedded SQL migrations
- migration checksum verification
- transaction-scoped advisory lock
- idempotent re-run from scratch or on already-migrated databases
